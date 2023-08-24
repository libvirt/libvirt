/*---------------------------------------------------------------------------*/
/*
 * Copyright (C) 2011-2015 Red Hat, Inc.
 * Copyright 2010, diateam (www.diateam.net)
 * Copyright (C) 2013. Doug Goldstein <cardoe@cardoe.com>
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
/*---------------------------------------------------------------------------*/

#include <config.h>

#include <fcntl.h>

#include "internal.h"
#include "virerror.h"
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "viruuid.h"
#include "vircommand.h"
#include "vmx.h"
#include "vmware_conf.h"
#include "vmware_driver.h"

/* Various places we may find the "vmrun" binary,
 * without a leading / it will be searched in PATH
 */
static const char * const vmrun_candidates[] = {
    "vmrun",
#ifdef __APPLE__
    "/Applications/VMware Fusion.app/Contents/Library/vmrun",
    "/Library/Application Support/VMware Fusion/vmrun",
#endif /* __APPLE__ */
};

static virDomainObj *
vmwareDomObjFromDomainLocked(struct vmware_driver *driver,
                             const unsigned char *uuid)
{
    virDomainObj *vm;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(vm = virDomainObjListFindByUUID(driver->domains, uuid))) {
        virUUIDFormat(uuid, uuidstr);

        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s'"), uuidstr);
        return NULL;
    }

    return vm;
}


static virDomainObj *
vmwareDomObjFromDomain(struct vmware_driver *driver,
                       const unsigned char *uuid)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    return vmwareDomObjFromDomainLocked(driver, uuid);
}


static void *
vmwareDataAllocFunc(void *opaque G_GNUC_UNUSED)
{
    vmwareDomainPtr dom;

    dom = g_new0(vmwareDomain, 1);

    dom->vmxPath = NULL;
    dom->gui = true;

    return dom;
}

static void
vmwareDataFreeFunc(void *data)
{
    vmwareDomainPtr dom = data;

    g_free(dom->vmxPath);
    g_free(dom);
}

static int
vmwareDomainDefPostParse(virDomainDef *def,
                         unsigned int parseFlags G_GNUC_UNUSED,
                         void *opaque G_GNUC_UNUSED,
                         void *parseOpaque G_GNUC_UNUSED)
{
    struct vmware_driver *driver = opaque;
    if (!virCapabilitiesDomainSupported(driver->caps, def->os.type,
                                        def->os.arch,
                                        def->virtType))
        return -1;

    return 0;
}

static int
vmwareDomainDeviceDefPostParse(virDomainDeviceDef *dev G_GNUC_UNUSED,
                               const virDomainDef *def G_GNUC_UNUSED,
                               unsigned int parseFlags G_GNUC_UNUSED,
                               void *opaque G_GNUC_UNUSED,
                               void *parseOpaque G_GNUC_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO &&
        dev->data.video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT)
        dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_VMVGA;

    return 0;
}

virDomainDefParserConfig vmwareDomainDefParserConfig = {
    .devicesPostParseCallback = vmwareDomainDeviceDefPostParse,
    .domainPostParseCallback = vmwareDomainDefPostParse,
    .defArch = VIR_ARCH_I686,
};

static virDomainXMLOption *
vmwareDomainXMLConfigInit(struct vmware_driver *driver)
{
    virDomainXMLPrivateDataCallbacks priv = { .alloc = vmwareDataAllocFunc,
                                              .free = vmwareDataFreeFunc };
    vmwareDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&vmwareDomainDefParserConfig, &priv,
                                 NULL, NULL, NULL, NULL);
}

static virDrvOpenStatus
vmwareConnectOpen(virConnectPtr conn,
                  virConnectAuthPtr auth G_GNUC_UNUSED,
                  virConf *conf G_GNUC_UNUSED,
                  unsigned int flags)
{
    struct vmware_driver *driver;
    size_t i;
    char *tmp;
    char *vmrun = NULL;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* If path isn't /session, then they typoed, so tell them correct path */
    if (STRNEQ(conn->uri->path, "/session")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected VMware URI path '%1$s', try vmwareplayer:///session, vmwarews:///session or vmwarefusion:///session"),
                       NULLSTR(conn->uri->path));
        return VIR_DRV_OPEN_ERROR;
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    driver = g_new0(struct vmware_driver, 1);

    /* Find vmrun, which is what this driver uses to communicate to
     * the VMware hypervisor. We look this up first since we use it
     * for auto detection of the backend
     */
    for (i = 0; i < G_N_ELEMENTS(vmrun_candidates); i++) {
        vmrun = virFindFileInPath(vmrun_candidates[i]);
        if (vmrun == NULL)
            continue;
        if (virFileResolveLink(vmrun, &driver->vmrun) < 0) {
            virReportSystemError(errno, _("unable to resolve symlink '%1$s'"), vmrun);
            goto cleanup;
        }
        VIR_FREE(vmrun);
        /* If we found one, we can stop looking */
        if (driver->vmrun)
            break;
    }

    if (driver->vmrun == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("vmrun utility is missing"));
        goto cleanup;
    }

    if (virMutexInit(&driver->lock) < 0)
        goto cleanup;

    if ((tmp = STRSKIP(conn->uri->scheme, "vmware")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse URI scheme '%1$s'"),
                       conn->uri->scheme);
        goto cleanup;
    }

    /* Match the non-'vmware' part of the scheme as the driver backend */
    driver->type = vmwareDriverTypeFromString(tmp);

    if (driver->type == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to find valid requested VMware backend '%1$s'"),
                       tmp);
        goto cleanup;
    }

    if (vmwareExtractVersion(driver) < 0)
        goto cleanup;

    if (!(driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(driver->caps = vmwareCapsInit()))
        goto cleanup;

    if (!(driver->xmlopt = vmwareDomainXMLConfigInit(driver)))
        goto cleanup;

    if (vmwareLoadDomains(driver) < 0)
        goto cleanup;

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    vmwareFreeDriver(driver);
    VIR_FREE(vmrun);
    return VIR_DRV_OPEN_ERROR;
};

static int
vmwareConnectClose(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;

    vmwareFreeDriver(driver);

    conn->privateData = NULL;

    return 0;
}

static const char *
vmwareConnectGetType(virConnectPtr conn G_GNUC_UNUSED)
{
    return "VMware";
}

static int
vmwareConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct vmware_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    *version = driver->version;
    return 0;
}

static int
vmwareUpdateVMStatus(struct vmware_driver *driver, virDomainObj *vm)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *outbuf = NULL;
    g_autofree char *vmxAbsolutePath = NULL;
    char *parsedVmxPath = NULL;
    char *str;
    char *saveptr = NULL;
    bool found = false;
    int oldState = virDomainObjGetState(vm, NULL);
    int newState;

    cmd = virCommandNewArgList(driver->vmrun, "-T",
                               vmwareDriverTypeToString(driver->type),
                               "list", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if (virFileResolveAllLinks(((vmwareDomainPtr) vm->privateData)->vmxPath,
                               &vmxAbsolutePath) < 0)
        return -1;

    for (str = outbuf; (parsedVmxPath = strtok_r(str, "\n", &saveptr)) != NULL;
         str = NULL) {

        if (!g_path_is_absolute(parsedVmxPath))
            continue;

        if (STREQ(parsedVmxPath, vmxAbsolutePath)) {
            found = true;
            /* If the vmx path is in the output, the domain is running or
             * is paused but we have no way to detect if it is paused or not. */
            if (oldState == VIR_DOMAIN_PAUSED)
                newState = oldState;
            else
                newState = VIR_DOMAIN_RUNNING;
            break;
        }
    }

    if (!found) {
        vm->def->id = -1;
        newState = VIR_DOMAIN_SHUTOFF;
    }

    virDomainObjSetState(vm, newState, 0);

    return 0;
}

static int
vmwareStopVM(struct vmware_driver *driver,
             virDomainObj *vm,
             virDomainShutoffReason reason)
{
    g_autoptr(virCommand) cmd = virCommandNew(driver->vmrun);

    virCommandAddArgList(cmd, "-T", vmwareDriverTypeToString(driver->type),
        "stop", ((vmwareDomainPtr) vm->privateData)->vmxPath, "soft", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    return 0;
}

static int
vmwareStartVM(struct vmware_driver *driver, virDomainObj *vm)
{
    g_autoptr(virCommand) cmd = virCommandNew(driver->vmrun);
    const char *vmxPath = ((vmwareDomainPtr) vm->privateData)->vmxPath;

    virCommandAddArgList(cmd, "-T", vmwareDriverTypeToString(driver->type),
                         "start", vmxPath, NULL);

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not in shutoff state"));
        return -1;
    }

    if (!((vmwareDomainPtr) vm->privateData)->gui)
        virCommandAddArg(cmd, NOGUI);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if ((vm->def->id = vmwareExtractPid(vmxPath)) < 0) {
        vmwareStopVM(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
        return -1;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

    return 0;
}

static virDomainPtr
vmwareDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    struct vmware_driver *driver = conn->privateData;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    char *vmx = NULL;
    char *vmxPath = NULL;
    vmwareDomainPtr pDomain = NULL;
    virVMXContext ctx;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    ctx.parseFileName = NULL;
    ctx.formatFileName = vmwareFormatVMXFileName;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = NULL;

    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", vmdef->name, "\n") < 0)
        goto cleanup;

    /* generate vmx file */
    vmx = virVMXFormatConfig(&ctx, driver->xmlopt, vmdef, 7);
    if (vmx == NULL)
        goto cleanup;

    if (vmwareVmxPath(vmdef, &vmxPath) < 0)
        goto cleanup;

    /* create vmx file */
    if (virFileWriteStr(vmxPath, vmx, S_IRUSR|S_IWUSR) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to write vmx file '%1$s'"), vmxPath);
        goto cleanup;
    }

    /* assign def */
    if (!(vm = virDomainObjListAdd(driver->domains,
                                   &vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    pDomain = vm->privateData;
    pDomain->vmxPath = g_strdup(vmxPath);

    vmwareDomainConfigDisplay(pDomain, vm->def);

    vm->persistent = 1;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, -1);

 cleanup:
    VIR_FREE(vmx);
    VIR_FREE(vmxPath);
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr
vmwareDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return vmwareDomainDefineXMLFlags(conn, xml, 0);
}

static int
vmwareDomainShutdownFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(0, -1);

    if (!(vm = vmwareDomObjFromDomainLocked(driver, dom->uuid)))
        goto cleanup;

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (vmwareStopVM(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN) < 0)
        goto cleanup;

    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;
 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmwareDomainShutdown(virDomainPtr dom)
{
    return vmwareDomainShutdownFlags(dom, 0);
}

static int
vmwareDomainDestroy(virDomainPtr dom)
{
    return vmwareDomainShutdownFlags(dom, 0);
}

static int
vmwareDomainDestroyFlags(virDomainPtr dom,
                         unsigned int flags)
{
    return vmwareDomainShutdownFlags(dom, flags);
}

static int
vmwareDomainSuspend(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    g_autoptr(virCommand) cmd = virCommandNew(driver->vmrun);

    virDomainObj *vm;
    int ret = -1;

    if (driver->type == VMWARE_DRIVER_PLAYER) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("vmplayer does not support libvirt suspend/resume (vmware pause/unpause) operation "));
        return ret;
    }

    if (!(vm = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    virCommandAddArgList(cmd, "-T", vmwareDriverTypeToString(driver->type),
                         "pause", ((vmwareDomainPtr) vm->privateData)->vmxPath,
                         NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmwareDomainResume(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    g_autoptr(virCommand) cmd = virCommandNew(driver->vmrun);

    virDomainObj *vm;
    int ret = -1;

    if (driver->type == VMWARE_DRIVER_PLAYER) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("vmplayer does not support libvirt suspend/resume (vmware pause/unpause) operation "));
        return ret;
    }

    if (!(vm = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in suspend state"));
        goto cleanup;
    }

    virCommandAddArgList(cmd, "-T", vmwareDriverTypeToString(driver->type),
                         "unpause", ((vmwareDomainPtr) vm->privateData)->vmxPath,
                         NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmwareDomainReboot(virDomainPtr dom, unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    g_autoptr(virCommand) cmd = virCommandNew(driver->vmrun);
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    virCommandAddArgList(cmd, "-T", vmwareDriverTypeToString(driver->type),
                         "reset", ((vmwareDomainPtr) vm->privateData)->vmxPath,
                         "soft", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static virDomainPtr
vmwareDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    struct vmware_driver *driver = conn->privateData;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    char *vmx = NULL;
    char *vmxPath = NULL;
    vmwareDomainPtr pDomain = NULL;
    virVMXContext ctx;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    ctx.parseFileName = NULL;
    ctx.formatFileName = vmwareFormatVMXFileName;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = NULL;

    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    /* generate vmx file */
    vmx = virVMXFormatConfig(&ctx, driver->xmlopt, vmdef, 7);
    if (vmx == NULL)
        goto cleanup;

    if (vmwareVmxPath(vmdef, &vmxPath) < 0)
        goto cleanup;

    /* create vmx file */
    if (virFileWriteStr(vmxPath, vmx, S_IRUSR|S_IWUSR) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to write vmx file '%1$s'"), vmxPath);
        goto cleanup;
    }

    /* assign def */
    if (!(vm = virDomainObjListAdd(driver->domains,
                                   &vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    pDomain = vm->privateData;
    pDomain->vmxPath = g_strdup(vmxPath);

    vmwareDomainConfigDisplay(pDomain, vm->def);

    if (vmwareStartVM(driver, vm) < 0) {
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    VIR_FREE(vmx);
    VIR_FREE(vmxPath);
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
vmwareDomainCreateWithFlags(virDomainPtr dom,
                            unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(0, -1);

    if (!(vm = vmwareDomObjFromDomainLocked(driver, dom->uuid)))
        goto cleanup;

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = vmwareStartVM(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmwareDomainCreate(virDomainPtr dom)
{
    return vmwareDomainCreateWithFlags(dom, 0);
}

static int
vmwareDomainUndefineFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(0, -1);

    if (!(vm = vmwareDomObjFromDomainLocked(driver, dom->uuid)))
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm))
        vm->persistent = 0;
    else
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmwareDomainUndefine(virDomainPtr dom)
{
    return vmwareDomainUndefineFlags(dom, 0);
}

static virDomainPtr
vmwareDomainLookupByID(virConnectPtr conn, int id)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        vm = virDomainObjListFindByID(driver->domains, id);
    }

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id '%1$d'"), id);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static char *
vmwareDomainGetOSType(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = vmwareDomObjFromDomain(driver, dom->uuid)))
        return NULL;

    ret = g_strdup(virDomainOSTypeToString(vm->def->os.type));

    virDomainObjEndAPI(&vm);
    return ret;
}


static virDomainPtr
vmwareDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    if (!(vm = vmwareDomObjFromDomain(driver, uuid)))
        return NULL;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
vmwareDomainLookupByName(virConnectPtr conn, const char *name)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        vm = virDomainObjListFindByName(driver->domains, name);
    }

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%1$s'"), name);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
vmwareDomainIsActive(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = virDomainObjIsActive(obj);

    virDomainObjEndAPI(&obj);
    return ret;
}


static int
vmwareDomainIsPersistent(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = obj->persistent;

    virDomainObjEndAPI(&obj);
    return ret;
}


static char *
vmwareDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = vmwareDomObjFromDomain(driver, dom->uuid)))
        return NULL;

    ret = virDomainDefFormat(vm->def, driver->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
vmwareConnectDomainXMLFromNative(virConnectPtr conn, const char *nativeFormat,
                                 const char *nativeConfig,
                                 unsigned int flags)
{
    struct vmware_driver *driver = conn->privateData;
    virVMXContext ctx;
    g_autoptr(virDomainDef) def = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (STRNEQ(nativeFormat, VMX_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unsupported config format '%1$s'"), nativeFormat);
        return NULL;
    }

    ctx.parseFileName = vmwareParseVMXFileName;
    ctx.formatFileName = NULL;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = NULL;

    def = virVMXParseConfig(&ctx, driver->xmlopt, driver->caps, nativeConfig);

    if (def != NULL)
        xml = virDomainDefFormat(def, driver->xmlopt,
                                 VIR_DOMAIN_DEF_FORMAT_INACTIVE);

    return xml;
}

static int vmwareDomainObjListUpdateDomain(virDomainObj *dom, void *data)
{
    struct vmware_driver *driver = data;
    virObjectLock(dom);
    ignore_value(vmwareUpdateVMStatus(driver, dom));
    virObjectUnlock(dom);
    return 0;
}

static void
vmwareDomainObjListUpdateAll(virDomainObjList *doms, struct vmware_driver *driver)
{
    virDomainObjListForEach(doms, false, vmwareDomainObjListUpdateDomain, driver);
}

static int
vmwareConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    vmwareDomainObjListUpdateAll(driver->domains, driver);
    return virDomainObjListNumOfDomains(driver->domains, false, NULL, NULL);
}

static int
vmwareConnectNumOfDomains(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    vmwareDomainObjListUpdateAll(driver->domains, driver);
    return virDomainObjListNumOfDomains(driver->domains, true, NULL, NULL);
}


static int
vmwareConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    struct vmware_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    vmwareDomainObjListUpdateAll(driver->domains, driver);
    return virDomainObjListGetActiveIDs(driver->domains, ids, nids, NULL, NULL);
}

static int
vmwareConnectListDefinedDomains(virConnectPtr conn,
                                char **const names, int nnames)
{
    struct vmware_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    vmwareDomainObjListUpdateAll(driver->domains, driver);
    return virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                            NULL, NULL);
}

static int
vmwareDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    info->state = virDomainObjGetState(vm, NULL);
    info->cpuTime = 0;
    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmwareDomainGetState(virDomainPtr dom,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (vmwareUpdateVMStatus(driver, vm) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmwareConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

static int
vmwareConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    struct vmware_driver *driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        vmwareDomainObjListUpdateAll(driver->domains, driver);
        ret = virDomainObjListExport(driver->domains, conn, domains,
                                     NULL, flags);
    }

    return ret;
}

static int
vmwareDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObj *obj;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(obj = vmwareDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = 0;

    virDomainObjEndAPI(&obj);
    return ret;
}



static virHypervisorDriver vmwareHypervisorDriver = {
    .name = "VMWARE",
    .connectOpen = vmwareConnectOpen, /* 0.8.7 */
    .connectClose = vmwareConnectClose, /* 0.8.7 */
    .connectGetType = vmwareConnectGetType, /* 0.8.7 */
    .connectGetVersion = vmwareConnectGetVersion, /* 0.8.7 */
    .connectListDomains = vmwareConnectListDomains, /* 0.8.7 */
    .connectNumOfDomains = vmwareConnectNumOfDomains, /* 0.8.7 */
    .connectListAllDomains = vmwareConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = vmwareDomainCreateXML, /* 0.8.7 */
    .domainLookupByID = vmwareDomainLookupByID, /* 0.8.7 */
    .domainLookupByUUID = vmwareDomainLookupByUUID, /* 0.8.7 */
    .domainLookupByName = vmwareDomainLookupByName, /* 0.8.7 */
    .domainSuspend = vmwareDomainSuspend, /* 0.8.7 */
    .domainResume = vmwareDomainResume, /* 0.8.7 */
    .domainShutdown = vmwareDomainShutdown, /* 0.8.7 */
    .domainShutdownFlags = vmwareDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = vmwareDomainReboot, /* 0.8.7 */
    .domainDestroy = vmwareDomainDestroy, /* 0.8.7 */
    .domainDestroyFlags = vmwareDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = vmwareDomainGetOSType, /* 0.8.7 */
    .domainGetInfo = vmwareDomainGetInfo, /* 0.8.7 */
    .domainGetState = vmwareDomainGetState, /* 0.9.2 */
    .domainGetXMLDesc = vmwareDomainGetXMLDesc, /* 0.8.7 */
    .connectDomainXMLFromNative = vmwareConnectDomainXMLFromNative, /* 0.9.11 */
    .connectListDefinedDomains = vmwareConnectListDefinedDomains, /* 0.8.7 */
    .connectNumOfDefinedDomains = vmwareConnectNumOfDefinedDomains, /* 0.8.7 */
    .domainCreate = vmwareDomainCreate, /* 0.8.7 */
    .domainCreateWithFlags = vmwareDomainCreateWithFlags, /* 0.8.7 */
    .domainDefineXML = vmwareDomainDefineXML, /* 0.8.7 */
    .domainDefineXMLFlags = vmwareDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = vmwareDomainUndefine, /* 0.8.7 */
    .domainUndefineFlags = vmwareDomainUndefineFlags, /* 0.9.4 */
    .domainIsActive = vmwareDomainIsActive, /* 0.8.7 */
    .domainIsPersistent = vmwareDomainIsPersistent, /* 0.8.7 */
    .connectIsAlive = vmwareConnectIsAlive, /* 0.9.8 */
    .domainHasManagedSaveImage = vmwareDomainHasManagedSaveImage, /* 1.2.13 */
};

static virConnectDriver vmwareConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "vmwareplayer", "vmwarews", "vmwarefusion", NULL },
    .hypervisorDriver = &vmwareHypervisorDriver,
};

int
vmwareRegister(void)
{
    return virRegisterConnectDriver(&vmwareConnectDriver,
                                    false);
}
