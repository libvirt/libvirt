/*
 * bhyve_driver.c: core driver methods for managing bhyve guests
 *
 * Copyright (C) 2014 Roman Bogorodskiy
 * Copyright (C) 2014-2015 Red Hat, Inc.
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

#include <fcntl.h>
#include <sys/utsname.h>

#include "virerror.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "configmake.h"
#include "viralloc.h"
#include "network_conf.h"
#include "interface_conf.h"
#include "domain_audit.h"
#include "domain_event.h"
#include "snapshot_conf.h"
#include "fdstream.h"
#include "storage_conf.h"
#include "node_device_conf.h"
#include "virdomainobjlist.h"
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
#include "virhostcpu.h"
#include "virhostmem.h"
#include "conf/domain_capabilities.h"

#include "bhyve_conf.h"
#include "bhyve_device.h"
#include "bhyve_driver.h"
#include "bhyve_command.h"
#include "bhyve_parse_command.h"
#include "bhyve_domain.h"
#include "bhyve_process.h"
#include "bhyve_capabilities.h"

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

static int
bhyveAutostartDomain(virDomainObjPtr vm, void *opaque)
{
    const struct bhyveAutostartData *data = opaque;
    int ret = 0;
    virObjectLock(vm);
    if (vm->autostart && !virDomainObjIsActive(vm)) {
        virResetLastError();
        ret = virBhyveProcessStart(data->conn, data->driver, vm,
                                   VIR_DOMAIN_RUNNING_BOOTED, 0);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to autostart VM '%s': %s"),
                           vm->def->name, virGetLastErrorMessage());
        }
    }
    virObjectUnlock(vm);
    return ret;
}

static void
bhyveAutostartDomains(bhyveConnPtr driver)
{
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen("bhyve:///system");
    /* Ignoring NULL conn which is mostly harmless here */

    struct bhyveAutostartData data = { driver, conn };

    virDomainObjListForEach(driver->domains, bhyveAutostartDomain, &data);

    virObjectUnref(conn);
}

/**
 * bhyveDriverGetCapabilities:
 *
 * Get a reference to the virCapsPtr instance for the
 * driver.
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCapsPtr instance or NULL
 */
virCapsPtr ATTRIBUTE_NONNULL(1)
bhyveDriverGetCapabilities(bhyveConnPtr driver)
{

    return virObjectRef(driver->caps);
}

static char *
bhyveConnectGetCapabilities(virConnectPtr conn)
{
    bhyveConnPtr privconn = conn->privateData;
    virCapsPtr caps;
    char *xml = NULL;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = bhyveDriverGetCapabilities(privconn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get Capabilities"));
        goto cleanup;
    }

    if (!(xml = virCapabilitiesFormatXML(caps)))
        goto cleanup;

 cleanup:
    virObjectUnref(caps);
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
                 virConfPtr conf ATTRIBUTE_UNUSED,
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

         if (STRNEQ_NULLABLE(conn->uri->path, "/system")) {
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
bhyveConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static char *
bhyveConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    bhyveConnPtr privconn = conn->privateData;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(0, NULL);

    if (virConnectGetSysinfoEnsureACL(conn) < 0)
        return NULL;

    if (!privconn->hostsysinfo) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Host SMBIOS information is not available"));
        return NULL;
    }

    if (virSysinfoFormat(&buf, privconn->hostsysinfo) < 0)
        return NULL;
    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}

static int
bhyveConnectGetVersion(virConnectPtr conn, unsigned long *version)
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

    if (virDomainObjIsActive(vm)) {
        if (virBhyveGetDomainTotalCpuStats(vm, &(info->cpuTime)) < 0)
            goto cleanup;
    } else {
        info->cpuTime = 0;
    }

    info->state = virDomainObjGetState(vm, NULL);
    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    if (vm)
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
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
bhyveDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
bhyveDomainSetAutostart(virDomainPtr domain, int autostart)
{
    virDomainObjPtr vm;
    char *configFile = NULL;
    char *autostartLink = NULL;
    int ret = -1;

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainSetAutostartEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if ((configFile = virDomainConfigFile(BHYVE_CONFIG_DIR, vm->def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virDomainConfigFile(BHYVE_AUTOSTART_DIR, vm->def->name)) == NULL)
            goto cleanup;

        if (autostart) {
            if (virFileMakePath(BHYVE_AUTOSTART_DIR) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %s"),
                                     BHYVE_AUTOSTART_DIR);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s' to '%s'"),
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
    }

    ret = 0;

 cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (vm)
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
    if (obj)
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
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static char *
bhyveDomainGetOSType(virDomainPtr dom)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (VIR_STRDUP(ret, virDomainOSTypeToString(vm->def->os.type)) < 0)
        goto cleanup;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *
bhyveDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    bhyveConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr vm;
    virCapsPtr caps = NULL;
    char *ret = NULL;

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(domain->conn, vm->def, flags) < 0)
        goto cleanup;

    caps = bhyveDriverGetCapabilities(privconn);
    if (!caps)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, caps,
                             virDomainDefFormatConvertXMLFlags(flags));

    virObjectUnref(caps);
 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static virDomainPtr
bhyveDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    bhyveConnPtr privconn = conn->privateData;
    virDomainPtr dom = NULL;
    virDomainDefPtr def = NULL;
    virDomainDefPtr oldDef = NULL;
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    virCapsPtr caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    caps = bhyveDriverGetCapabilities(privconn);
    if (!caps)
        return NULL;

    if ((def = virDomainDefParseString(xml, caps, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(privconn->domains, def,
                                   privconn->xmlopt,
                                   0, &oldDef)))
        goto cleanup;
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(BHYVE_CONFIG_DIR, caps,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainObjListRemove(privconn->domains, vm);
        vm = NULL;
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
    virObjectUnref(caps);
    virDomainDefFree(def);
    virDomainDefFree(oldDef);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);

    return dom;
}

static virDomainPtr
bhyveDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return bhyveDomainDefineXMLFlags(conn, xml, 0);
}

static int
bhyveDomainUndefine(virDomainPtr domain)
{
    bhyveConnPtr privconn = domain->conn->privateData;
    virObjectEventPtr event = NULL;
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

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_UNDEFINED,
                                              VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(privconn->domains, vm);
        vm = NULL;
    }

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
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

static char *
bhyveConnectDomainXMLToNative(virConnectPtr conn,
                              const char *format,
                              const char *xmlData,
                              unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bhyveConnPtr privconn = conn->privateData;
    virDomainDefPtr def = NULL;
    virCommandPtr cmd = NULL, loadcmd = NULL;
    virCapsPtr caps = NULL;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STRNEQ(format, BHYVE_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unsupported config type %s"), format);
        goto cleanup;
    }

    if (!(caps = bhyveDriverGetCapabilities(privconn)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xmlData, caps, privconn->xmlopt,
                                        NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        goto cleanup;

    if (def->os.bootloader == NULL &&
        def->os.loader) {

        if ((def->os.loader->readonly != VIR_TRISTATE_BOOL_YES) ||
            (def->os.loader->type != VIR_DOMAIN_LOADER_TYPE_PFLASH)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only read-only pflash is supported."));
            goto cleanup;
        }

        if ((bhyveDriverGetCaps(conn) & BHYVE_CAP_LPC_BOOTROM) == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Installed bhyve binary does not support "
                          "bootrom"));
            goto cleanup;
        }
    } else {
        if (!(loadcmd = virBhyveProcessBuildLoadCmd(conn, def, "<device.map>",
                                                NULL)))
            goto cleanup;

        virBufferAdd(&buf, virCommandToString(loadcmd), -1);
        virBufferAddChar(&buf, '\n');
    }

    if (!(cmd = virBhyveProcessBuildBhyveCmd(conn, def, true)))
        goto cleanup;

    virBufferAdd(&buf, virCommandToString(cmd), -1);

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    ret = virBufferContentAndReset(&buf);

 cleanup:
    virCommandFree(loadcmd);
    virCommandFree(cmd);
    virDomainDefFree(def);
    virObjectUnref(caps);
    return ret;
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
    if (vm)
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
    virDomainObjEndAPI(&vm);
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
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static int
bhyveDomainCreateWithFlags(virDomainPtr dom,
                           unsigned int flags)
{
    bhyveConnPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
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

    if (ret == 0)
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STARTED,
                                                  VIR_DOMAIN_EVENT_STARTED_BOOTED);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
bhyveDomainCreate(virDomainPtr dom)
{
    return bhyveDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
bhyveDomainCreateXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    bhyveConnPtr privconn = conn->privateData;
    virDomainPtr dom = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    virCapsPtr caps = NULL;
    unsigned int start_flags = 0;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;
    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_BHYVE_PROCESS_START_AUTODESTROY;

    caps = bhyveDriverGetCapabilities(privconn);
    if (!caps)
        return NULL;

    if ((def = virDomainDefParseString(xml, caps, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(privconn->domains, def,
                                   privconn->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE, NULL)))
        goto cleanup;
    def = NULL;

    if (virBhyveProcessStart(conn, privconn, vm,
                             VIR_DOMAIN_RUNNING_BOOTED,
                             start_flags) < 0) {
        /* If domain is not persistent, remove its data */
        if (!vm->persistent) {
            virDomainObjListRemove(privconn->domains, vm);
            vm = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_BOOTED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    virObjectUnref(caps);
    virDomainDefFree(def);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);

    return dom;
}

static int
bhyveDomainDestroy(virDomainPtr dom)
{
    bhyveConnPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
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
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (!vm->persistent) {
        virDomainObjListRemove(privconn->domains, vm);
        vm = NULL;
    }

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
bhyveDomainShutdown(virDomainPtr dom)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainShutdownEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    ret = virBhyveProcessShutdown(vm);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
bhyveDomainOpenConsole(virDomainPtr dom,
                       const char *dev_name ATTRIBUTE_UNUSED,
                       virStreamPtr st,
                       unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainChrDefPtr chr = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!vm->def->nserials) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no console devices available"));
        goto cleanup;
    }

    chr = vm->def->serials[0];

    if (virFDStreamOpenPTY(st, chr->source->data.nmdm.slave,
                           0, 0, O_RDWR) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
bhyveDomainSetMetadata(virDomainPtr dom,
                       int type,
                       const char *metadata,
                       const char *key,
                       const char *uri,
                       unsigned int flags)
{
    bhyveConnPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    virCapsPtr caps = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = bhyveDomObjFromDomain(dom)))
        return -1;

    if (virDomainSetMetadataEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = bhyveDriverGetCapabilities(privconn)))
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri, caps,
                                  privconn->xmlopt, BHYVE_STATE_DIR,
                                  BHYVE_CONFIG_DIR, flags);

    if (ret == 0) {
        virObjectEventPtr ev = NULL;
        ev = virDomainEventMetadataChangeNewFromObj(vm, type, uri);
        virObjectEventStateQueue(privconn->domainEventState, ev);
    }


 cleanup:
    virObjectUnref(caps);
    virObjectUnlock(vm);
    return ret;
}

static char *
bhyveDomainGetMetadata(virDomainPtr dom,
                      int type,
                      const char *uri,
                      unsigned int flags)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = bhyveDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetMetadataEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjGetMetadata(vm, type, uri, flags);

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

    return virHostCPUGetStats(cpuNum, params, nparams, flags);
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

    return virHostMemGetStats(cellNum, params, nparams, flags);
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
    virSysinfoDefFree(bhyve_driver->hostsysinfo);
    virObjectUnref(bhyve_driver->closeCallbacks);
    virObjectUnref(bhyve_driver->domainEventState);
    virObjectUnref(bhyve_driver->config);

    virMutexDestroy(&bhyve_driver->lock);
    VIR_FREE(bhyve_driver);

    return 0;
}

static int
bhyveStateInitialize(bool privileged,
                     virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                     void *opaque ATTRIBUTE_UNUSED)
{
    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return 0;
    }

    if (VIR_ALLOC(bhyve_driver) < 0)
        return -1;

    if (virMutexInit(&bhyve_driver->lock) < 0) {
        VIR_FREE(bhyve_driver);
        return -1;
    }

    if (!(bhyve_driver->closeCallbacks = virCloseCallbacksNew()))
        goto cleanup;

    if (!(bhyve_driver->caps = virBhyveCapsBuild()))
        goto cleanup;

    if (virBhyveProbeCaps(&bhyve_driver->bhyvecaps) < 0)
        goto cleanup;

    if (virBhyveProbeGrubCaps(&bhyve_driver->grubcaps) < 0)
        goto cleanup;

    if (!(bhyve_driver->xmlopt = virBhyveDriverCreateXMLConf(bhyve_driver)))
        goto cleanup;

    if (!(bhyve_driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(bhyve_driver->domainEventState = virObjectEventStateNew()))
        goto cleanup;

    bhyve_driver->hostsysinfo = virSysinfoRead();

    if (!(bhyve_driver->config = virBhyveDriverConfigNew()))
        goto cleanup;

    if (virBhyveLoadDriverConfig(bhyve_driver->config, SYSCONFDIR "/libvirt/bhyve.conf") < 0)
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
                             BHYVE_STATE_DIR);
        goto cleanup;
    }

    if (virDomainObjListLoadAllConfigs(bhyve_driver->domains,
                                       BHYVE_STATE_DIR,
                                       NULL, 1,
                                       bhyve_driver->caps,
                                       bhyve_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    if (virDomainObjListLoadAllConfigs(bhyve_driver->domains,
                                       BHYVE_CONFIG_DIR,
                                       BHYVE_AUTOSTART_DIR, 0,
                                       bhyve_driver->caps,
                                       bhyve_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    virBhyveProcessReconnectAll(bhyve_driver);

    return 0;

 cleanup:
    bhyveStateCleanup();
    return -1;
}

unsigned
bhyveDriverGetCaps(virConnectPtr conn)
{
    bhyveConnPtr driver = conn->privateData;

    if (driver != NULL)
        return driver->bhyvecaps;
    return 0;
}

unsigned
bhyveDriverGetGrubCaps(virConnectPtr conn)
{
    bhyveConnPtr driver = conn->privateData;

    if (driver != NULL)
        return driver->grubcaps;
    return 0;
}

static void
bhyveStateAutoStart(void)
{
    if (!bhyve_driver)
        return;

    bhyveAutostartDomains(bhyve_driver);
}

static int
bhyveConnectGetMaxVcpus(virConnectPtr conn,
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
    unsigned long long freeMem;

    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    if (virHostMemGetInfo(NULL, &freeMem) < 0)
        return 0;

    return freeMem;
}

static int
bhyveNodeGetCPUMap(virConnectPtr conn,
                   unsigned char **cpumap,
                   unsigned int *online,
                   unsigned int flags)
{
    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    return virHostCPUGetMap(cpumap, online, flags);
}

static int
bhyveNodeGetMemoryParameters(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    if (virNodeGetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemGetParameters(params, nparams, flags);
}

static int
bhyveNodeSetMemoryParameters(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags)
{
    if (virNodeSetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemSetParameters(params, nparams, flags);
}

static char *
bhyveConnectBaselineCPU(virConnectPtr conn,
                        const char **xmlCPUs,
                        unsigned int ncpus,
                        unsigned int flags)
{
    char *cpu = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (virConnectBaselineCPUEnsureACL(conn) < 0)
        goto cleanup;

    cpu = cpuBaselineXML(xmlCPUs, ncpus, NULL, 0, flags);

 cleanup:
    return cpu;
}

static int
bhyveConnectCompareCPU(virConnectPtr conn,
                       const char *xmlDesc,
                       unsigned int flags)
{
    bhyveConnPtr driver = conn->privateData;
    int ret = VIR_CPU_COMPARE_ERROR;
    virCapsPtr caps = NULL;
    bool failIncompatible;

    virCheckFlags(VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE,
                  VIR_CPU_COMPARE_ERROR);

    if (virConnectCompareCPUEnsureACL(conn) < 0)
        goto cleanup;

    failIncompatible = !!(flags & VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE);

    if (!(caps = bhyveDriverGetCapabilities(driver)))
        goto cleanup;

    if (!caps->host.cpu ||
        !caps->host.cpu->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("cannot get host CPU capabilities"));
        } else {
            VIR_WARN("cannot get host CPU capabilities");
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        }
    } else {
        ret = virCPUCompareXML(caps->host.arch, caps->host.cpu,
                               xmlDesc, failIncompatible);
    }

 cleanup:
    virObjectUnref(caps);
    return ret;
}

static int
bhyveConnectDomainEventRegisterAny(virConnectPtr conn,
                                   virDomainPtr dom,
                                   int eventID,
                                   virConnectDomainEventGenericCallback callback,
                                   void *opaque,
                                   virFreeCallback freecb)
{
    bhyveConnPtr privconn = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegisterID(conn,
                                      privconn->domainEventState,
                                      dom, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}

static int
bhyveConnectDomainEventDeregisterAny(virConnectPtr conn,
                                     int callbackID)
{
    bhyveConnPtr privconn = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        privconn->domainEventState,
                                        callbackID) < 0)
        return -1;

    return 0;
}

static int
bhyveDomainHasManagedSaveImage(virDomainPtr domain, unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainHasManagedSaveImageEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static const char *
bhyveConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "BHYVE";
}

static int bhyveConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
bhyveConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}

static int
bhyveConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}

static char *
bhyveConnectDomainXMLFromNative(virConnectPtr conn,
                                const char *nativeFormat,
                                const char *nativeConfig,
                                unsigned int flags)
{
    char *xml = NULL;
    virDomainDefPtr def = NULL;
    bhyveConnPtr privconn = conn->privateData;
    virCapsPtr capabilities = NULL;
    unsigned caps = bhyveDriverGetCaps(conn);

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        return NULL;

    capabilities = bhyveDriverGetCapabilities(privconn);
    if (!capabilities)
        return NULL;

    if (STRNEQ(nativeFormat, BHYVE_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        goto cleanup;
    }

    def = bhyveParseCommandLineString(nativeConfig, caps, privconn->xmlopt);
    if (def == NULL)
        goto cleanup;

    xml = virDomainDefFormat(def, capabilities, 0);

 cleanup:
    virObjectUnref(capabilities);
    virDomainDefFree(def);
    return xml;
}

static char *
bhyveConnectGetDomainCapabilities(virConnectPtr conn,
                                  const char *emulatorbin,
                                  const char *arch_str,
                                  const char *machine,
                                  const char *virttype_str,
                                  unsigned int flags)
{
    virDomainCapsPtr caps = NULL;
    char *ret = NULL;
    int virttype = VIR_DOMAIN_VIRT_BHYVE;
    int arch = virArchFromHost(); /* virArch */

    virCheckFlags(0, ret);

    if (virConnectGetDomainCapabilitiesEnsureACL(conn) < 0)
        return ret;

    if (virttype_str &&
        (virttype = virDomainVirtTypeFromString(virttype_str)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %s"),
                       virttype_str);
        goto cleanup;
    }

    if (virttype != VIR_DOMAIN_VIRT_BHYVE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %s"),
                       virttype_str);
        goto cleanup;
    }

    if (arch_str && (arch = virArchFromString(arch_str)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown architecture: %s"),
                       arch_str);
        goto cleanup;
    }

    if (!ARCH_IS_X86(arch)) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("unsupported architecture: %s"),
                       virArchToString(arch));
        goto cleanup;
    }

    if (emulatorbin == NULL) {
        emulatorbin = "/usr/sbin/bhyve";
    } else if (STRNEQ(emulatorbin, "/usr/sbin/bhyve")) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown emulator binary: %s"),
                       emulatorbin);
        goto cleanup;
    }

    if (!(caps = virBhyveDomainCapsBuild(conn->privateData, emulatorbin,
                                         machine, arch, virttype)))
        goto cleanup;

    ret = virDomainCapsFormat(caps);

 cleanup:
    virObjectUnref(caps);
    return ret;
}

static virHypervisorDriver bhyveHypervisorDriver = {
    .name = "bhyve",
    .connectOpen = bhyveConnectOpen, /* 1.2.2 */
    .connectClose = bhyveConnectClose, /* 1.2.2 */
    .connectGetVersion = bhyveConnectGetVersion, /* 1.2.2 */
    .connectGetHostname = bhyveConnectGetHostname, /* 1.2.2 */
    .connectGetSysinfo = bhyveConnectGetSysinfo, /* 1.2.5 */
    .domainGetInfo = bhyveDomainGetInfo, /* 1.2.2 */
    .domainGetState = bhyveDomainGetState, /* 1.2.2 */
    .connectGetCapabilities = bhyveConnectGetCapabilities, /* 1.2.2 */
    .connectListDomains = bhyveConnectListDomains, /* 1.2.2 */
    .connectNumOfDomains = bhyveConnectNumOfDomains, /* 1.2.2 */
    .connectListAllDomains = bhyveConnectListAllDomains, /* 1.2.2 */
    .connectListDefinedDomains = bhyveConnectListDefinedDomains, /* 1.2.2 */
    .connectNumOfDefinedDomains = bhyveConnectNumOfDefinedDomains, /* 1.2.2 */
    .connectDomainXMLToNative = bhyveConnectDomainXMLToNative, /* 1.2.5 */
    .domainCreate = bhyveDomainCreate, /* 1.2.2 */
    .domainCreateWithFlags = bhyveDomainCreateWithFlags, /* 1.2.3 */
    .domainCreateXML = bhyveDomainCreateXML, /* 1.2.4 */
    .domainDestroy = bhyveDomainDestroy, /* 1.2.2 */
    .domainShutdown = bhyveDomainShutdown, /* 1.3.3 */
    .domainLookupByUUID = bhyveDomainLookupByUUID, /* 1.2.2 */
    .domainLookupByName = bhyveDomainLookupByName, /* 1.2.2 */
    .domainLookupByID = bhyveDomainLookupByID, /* 1.2.3 */
    .domainDefineXML = bhyveDomainDefineXML, /* 1.2.2 */
    .domainDefineXMLFlags = bhyveDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = bhyveDomainUndefine, /* 1.2.2 */
    .domainGetOSType = bhyveDomainGetOSType, /* 1.2.21 */
    .domainGetXMLDesc = bhyveDomainGetXMLDesc, /* 1.2.2 */
    .domainIsActive = bhyveDomainIsActive, /* 1.2.2 */
    .domainIsPersistent = bhyveDomainIsPersistent, /* 1.2.2 */
    .domainGetAutostart = bhyveDomainGetAutostart, /* 1.2.4 */
    .domainSetAutostart = bhyveDomainSetAutostart, /* 1.2.4 */
    .domainOpenConsole = bhyveDomainOpenConsole, /* 1.2.4 */
    .domainSetMetadata = bhyveDomainSetMetadata, /* 1.2.4 */
    .domainGetMetadata = bhyveDomainGetMetadata, /* 1.2.4 */
    .nodeGetCPUStats = bhyveNodeGetCPUStats, /* 1.2.2 */
    .nodeGetMemoryStats = bhyveNodeGetMemoryStats, /* 1.2.2 */
    .nodeGetInfo = bhyveNodeGetInfo, /* 1.2.3 */
    .connectGetMaxVcpus = bhyveConnectGetMaxVcpus, /* 1.2.3 */
    .nodeGetFreeMemory = bhyveNodeGetFreeMemory, /* 1.2.3 */
    .nodeGetCPUMap = bhyveNodeGetCPUMap, /* 1.2.3 */
    .nodeGetMemoryParameters = bhyveNodeGetMemoryParameters, /* 1.2.3 */
    .nodeSetMemoryParameters = bhyveNodeSetMemoryParameters, /* 1.2.3 */
    .connectBaselineCPU = bhyveConnectBaselineCPU, /* 1.2.4 */
    .connectCompareCPU = bhyveConnectCompareCPU, /* 1.2.4 */
    .connectDomainEventRegisterAny = bhyveConnectDomainEventRegisterAny, /* 1.2.5 */
    .connectDomainEventDeregisterAny = bhyveConnectDomainEventDeregisterAny, /* 1.2.5 */
    .domainHasManagedSaveImage = bhyveDomainHasManagedSaveImage, /* 1.2.13 */
    .connectGetType = bhyveConnectGetType, /* 1.3.5 */
    .connectIsAlive = bhyveConnectIsAlive, /* 1.3.5 */
    .connectIsSecure = bhyveConnectIsSecure, /* 1.3.5 */
    .connectIsEncrypted = bhyveConnectIsEncrypted, /* 1.3.5 */
    .connectDomainXMLFromNative = bhyveConnectDomainXMLFromNative, /* 2.1.0 */
    .connectGetDomainCapabilities = bhyveConnectGetDomainCapabilities, /* 2.1.0 */
};


static virConnectDriver bhyveConnectDriver = {
    .hypervisorDriver = &bhyveHypervisorDriver,
};

static virStateDriver bhyveStateDriver = {
    .name = "bhyve",
    .stateInitialize = bhyveStateInitialize,
    .stateAutoStart = bhyveStateAutoStart,
    .stateCleanup = bhyveStateCleanup,
};

int
bhyveRegister(void)
{
    if (virRegisterConnectDriver(&bhyveConnectDriver,
                                 true) < 0)
        return -1;
    if (virRegisterStateDriver(&bhyveStateDriver) < 0)
        return -1;
    return 0;
}
