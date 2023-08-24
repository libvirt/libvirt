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
#include "virfdstream.h"
#include "storage_conf.h"
#include "node_device_conf.h"
#include "virdomainobjlist.h"
#include "virxml.h"
#include "virthread.h"
#include "virlog.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virtypedparam.h"
#include "virrandom.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "viraccessapicheck.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "virportallocator.h"
#include "conf/domain_capabilities.h"
#include "virutil.h"

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

struct _bhyveConn *bhyve_driver = NULL;

static int
bhyveAutostartDomain(virDomainObj *vm, void *opaque)
{
    const struct bhyveAutostartData *data = opaque;
    int ret = 0;
    VIR_LOCK_GUARD lock = virObjectLockGuard(vm);

    if (vm->autostart && !virDomainObjIsActive(vm)) {
        virResetLastError();
        ret = virBhyveProcessStart(data->conn, vm,
                                   VIR_DOMAIN_RUNNING_BOOTED, 0);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to autostart VM '%1$s': %2$s"),
                           vm->def->name, virGetLastErrorMessage());
        }
    }
    return ret;
}

static void
bhyveAutostartDomains(struct _bhyveConn *driver)
{
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen("bhyve:///system");
    /* Ignoring NULL conn which is mostly harmless here */

    struct bhyveAutostartData data = { driver, conn };

    virDomainObjListForEach(driver->domains, false, bhyveAutostartDomain, &data);

    virObjectUnref(conn);
}

/**
 * bhyveDriverGetCapabilities:
 *
 * Get a reference to the virCaps *instance for the
 * driver.
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCaps *instance or NULL
 */
virCaps *ATTRIBUTE_NONNULL(1)
bhyveDriverGetCapabilities(struct _bhyveConn *driver)
{
    return virObjectRef(driver->caps);
}

static char *
bhyveConnectGetCapabilities(virConnectPtr conn)
{
    struct _bhyveConn *privconn = conn->privateData;
    g_autoptr(virCaps) caps = NULL;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = bhyveDriverGetCapabilities(privconn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get Capabilities"));
        return NULL;
    }

    return virCapabilitiesFormatXML(caps);
}

static virDomainObj *
bhyveDomObjFromDomain(virDomainPtr domain)
{
    virDomainObj *vm;
    struct _bhyveConn *privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s' (%2$s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}


static int
bhyveConnectURIProbe(char **uri)
{
    if (bhyve_driver == NULL)
        return 0;

    *uri = g_strdup("bhyve:///system");
    return 1;
}


static virDrvOpenStatus
bhyveConnectOpen(virConnectPtr conn,
                 virConnectAuthPtr auth G_GNUC_UNUSED,
                 virConf *conf G_GNUC_UNUSED,
                 unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected bhyve URI path '%1$s', try bhyve:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if (bhyve_driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("bhyve state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = bhyve_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int
bhyveConnectClose(virConnectPtr conn)
{
    struct _bhyveConn *privconn = conn->privateData;

    virCloseCallbacksDomainRunForConn(privconn->domains, conn);
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
    struct _bhyveConn *privconn = conn->privateData;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

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

    return virBufferContentAndReset(&buf);
}

static int
bhyveConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    unsigned long long tmpver;
    struct utsname ver;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    uname(&ver);

    if (virStringParseVersion(&tmpver, ver.release, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown release: %1$s"), ver.release);
        return -1;
    }

    *version = tmpver;

    return 0;
}

static int
bhyveDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    virDomainObj *vm;
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
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
bhyveDomainGetState(virDomainPtr domain,
                    int *state,
                    int *reason,
                    unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(domain->conn, vm->def) < 0)
       goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
bhyveDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
bhyveDomainSetAutostart(virDomainPtr domain, int autostart)
{
    virDomainObj *vm;
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
            if (g_mkdir_with_parents(BHYVE_AUTOSTART_DIR, 0777) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %1$s"),
                                     BHYVE_AUTOSTART_DIR);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%1$s' to '%2$s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%1$s'"),
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
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
bhyveDomainIsActive(virDomainPtr domain)
{
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(domain->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int
bhyveDomainIsPersistent(virDomainPtr domain)
{
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainIsPersistentEnsureACL(domain->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static char *
bhyveDomainGetOSType(virDomainPtr dom)
{
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = g_strdup(virDomainOSTypeToString(vm->def->os.type));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
bhyveDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    struct _bhyveConn *privconn = domain->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(domain->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, privconn->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static virDomainPtr
bhyveDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    struct _bhyveConn *privconn = conn->privateData;
    virDomainPtr dom = NULL;
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(virDomainDef) oldDef = NULL;
    virDomainObj *vm = NULL;
    virObjectEvent *event = NULL;
    g_autoptr(virCaps) caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    caps = bhyveDriverGetCapabilities(privconn);
    if (!caps)
        return NULL;

    if ((def = virDomainDefParseString(xml, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(privconn->domains, &def,
                                   privconn->xmlopt,
                                   0, &oldDef)))
        goto cleanup;
    vm->persistent = 1;

    if (virDomainDefSave(vm->newDef ? vm->newDef : vm->def,
                         privconn->xmlopt, BHYVE_CONFIG_DIR) < 0) {
        virDomainObjListRemove(privconn->domains, vm);
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
    virObjectEventStateQueue(privconn->domainEventState, event);

    return dom;
}

static virDomainPtr
bhyveDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return bhyveDomainDefineXMLFlags(conn, xml, 0);
}

static int
bhyveDomainUndefineFlags(virDomainPtr domain, unsigned int flags)
{
    struct _bhyveConn *privconn = domain->conn->privateData;
    virObjectEvent *event = NULL;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);
    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainUndefineFlagsEnsureACL(domain->conn, vm->def) < 0)
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

    if (virDomainObjIsActive(vm))
        vm->persistent = 0;
    else
        virDomainObjListRemove(privconn->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
bhyveDomainUndefine(virDomainPtr domain)
{
    return bhyveDomainUndefineFlags(domain, 0);
}

static int
bhyveConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    struct _bhyveConn *privconn = conn->privateData;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetActiveIDs(privconn->domains, ids, maxids,
                                        virConnectListDomainsCheckACL, conn);
}

static int
bhyveConnectNumOfDomains(virConnectPtr conn)
{
    struct _bhyveConn *privconn = conn->privateData;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(privconn->domains, true,
                                        virConnectNumOfDomainsCheckACL, conn);
}

static int
bhyveConnectListDefinedDomains(virConnectPtr conn, char **const names,
                               int maxnames)
{
    struct _bhyveConn *privconn = conn->privateData;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    memset(names, 0, sizeof(*names) * maxnames);
    return virDomainObjListGetInactiveNames(privconn->domains, names,
                                            maxnames,
                                            virConnectListDefinedDomainsCheckACL,
                                            conn);
}

static int
bhyveConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct _bhyveConn *privconn = conn->privateData;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(privconn->domains, false,
                                        virConnectNumOfDefinedDomainsCheckACL,
                                        conn);
}

static char *
bhyveConnectDomainXMLToNative(virConnectPtr conn,
                              const char *format,
                              const char *xmlData,
                              unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    struct _bhyveConn *privconn = conn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autoptr(virCommand) loadcmd = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        return NULL;

    if (STRNEQ(format, BHYVE_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unsupported config type %1$s"), format);
        return NULL;
    }

    if (!(def = virDomainDefParseString(xmlData, privconn->xmlopt,
                                        NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        return NULL;

    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        return NULL;

    if (def->os.bootloader == NULL &&
        def->os.loader) {

        if (!virDomainDefHasOldStyleROUEFI(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only read-only pflash is supported."));
            return NULL;
        }

        if ((bhyveDriverGetBhyveCaps(privconn) & BHYVE_CAP_LPC_BOOTROM) == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Installed bhyve binary does not support bootrom"));
            return NULL;
        }
    } else {
        if (!(loadcmd = virBhyveProcessBuildLoadCmd(privconn, def,
                                                    "<device.map>", NULL)))
            return NULL;

        virCommandToStringBuf(loadcmd, &buf, false, false);
        virBufferAddChar(&buf, '\n');
    }

    if (!(cmd = virBhyveProcessBuildBhyveCmd(privconn, def, true)))
        return NULL;

    virCommandToStringBuf(cmd, &buf, false, false);

    return virBufferContentAndReset(&buf);
}

static int
bhyveConnectListAllDomains(virConnectPtr conn,
                           virDomainPtr **domains,
                           unsigned int flags)
{
    struct _bhyveConn *privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListExport(privconn->domains, conn, domains,
                                  virConnectListAllDomainsCheckACL, flags);
}

static virDomainPtr
bhyveDomainLookupByUUID(virConnectPtr conn,
                        const unsigned char *uuid)
{
    struct _bhyveConn *privconn = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(privconn->domains, uuid);

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

static virDomainPtr bhyveDomainLookupByName(virConnectPtr conn,
                                            const char *name)
{
    struct _bhyveConn *privconn = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(privconn->domains, name);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%1$s'"), name);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
bhyveDomainLookupByID(virConnectPtr conn,
                      int id)
{
    struct _bhyveConn *privconn = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(privconn->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching ID '%1$d'"), id);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
bhyveDomainCreateWithFlags(virDomainPtr dom,
                           unsigned int flags)
{
    struct _bhyveConn *privconn = dom->conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
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

    ret = virBhyveProcessStart(dom->conn, vm,
                               VIR_DOMAIN_RUNNING_BOOTED,
                               start_flags);

    if (ret == 0)
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STARTED,
                                                  VIR_DOMAIN_EVENT_STARTED_BOOTED);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    struct _bhyveConn *privconn = conn->privateData;
    virDomainPtr dom = NULL;
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *vm = NULL;
    virObjectEvent *event = NULL;
    unsigned int start_flags = 0;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;
    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_BHYVE_PROCESS_START_AUTODESTROY;

    if ((def = virDomainDefParseString(xml, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(privconn->domains, &def,
                                   privconn->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE, NULL)))
        goto cleanup;

    if (virBhyveProcessStart(conn, vm,
                             VIR_DOMAIN_RUNNING_BOOTED,
                             start_flags) < 0) {
        /* If domain is not persistent, remove its data */
        if (!vm->persistent)
            virDomainObjListRemove(privconn->domains, vm);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_BOOTED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);

    return dom;
}

static int
bhyveDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn = dom->conn;
    struct _bhyveConn *privconn = conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    ret = virBhyveProcessStop(privconn, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (!vm->persistent)
        virDomainObjListRemove(privconn->domains, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
bhyveDomainDestroy(virDomainPtr dom)
{
    return bhyveDomainDestroyFlags(dom, 0);
}

static int
bhyveDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    ret = virBhyveProcessShutdown(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
bhyveDomainShutdown(virDomainPtr dom)
{
    return bhyveDomainShutdownFlags(dom, 0);
}

static int
bhyveDomainReboot(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn = dom->conn;
    virDomainObj *vm;
    bhyveDomainObjPrivate *priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_REBOOT_ACPI_POWER_BTN, -1);

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainRebootEnsureACL(conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    priv = vm->privateData;
    bhyveMonitorSetReboot(priv->mon);

    ret = virBhyveProcessShutdown(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
bhyveDomainOpenConsole(virDomainPtr dom,
                       const char *dev_name G_GNUC_UNUSED,
                       virStreamPtr st,
                       unsigned int flags)
{
    virDomainObj *vm = NULL;
    virDomainChrDef *chr = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

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
    virDomainObjEndAPI(&vm);
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
    virConnectPtr conn = dom->conn;
    struct _bhyveConn *privconn = conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = bhyveDomObjFromDomain(dom)))
        return -1;

    if (virDomainSetMetadataEnsureACL(conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri,
                                  privconn->xmlopt, BHYVE_STATE_DIR,
                                  BHYVE_CONFIG_DIR, flags);

    if (ret == 0) {
        virObjectEvent *ev = NULL;
        ev = virDomainEventMetadataChangeNewFromObj(vm, type, uri);
        virObjectEventStateQueue(privconn->domainEventState, ev);
    }


 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
bhyveDomainGetMetadata(virDomainPtr dom,
                      int type,
                      const char *uri,
                      unsigned int flags)
{
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = bhyveDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetMetadataEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjGetMetadata(vm, type, uri, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
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

    return virCapabilitiesGetNodeInfo(nodeinfo);
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
    virObjectUnref(bhyve_driver->domainEventState);
    virObjectUnref(bhyve_driver->config);
    virPortAllocatorRangeFree(bhyve_driver->remotePorts);

    if (bhyve_driver->lockFD != -1)
        virPidFileRelease(BHYVE_STATE_DIR, "driver", bhyve_driver->lockFD);

    virMutexDestroy(&bhyve_driver->lock);
    VIR_FREE(bhyve_driver);

    return 0;
}

static int
bhyveStateInitialize(bool privileged,
                     const char *root,
                     bool monolithic G_GNUC_UNUSED,
                     virStateInhibitCallback callback G_GNUC_UNUSED,
                     void *opaque G_GNUC_UNUSED)
{
    bool autostart = true;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return VIR_DRV_STATE_INIT_SKIPPED;
    }

    bhyve_driver = g_new0(bhyveConn, 1);

    bhyve_driver->lockFD = -1;
    if (virMutexInit(&bhyve_driver->lock) < 0) {
        VIR_FREE(bhyve_driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

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

    if (!(bhyve_driver->remotePorts = virPortAllocatorRangeNew(_("display"),
                                                               5900, 65535)))
        goto cleanup;

    bhyve_driver->hostsysinfo = virSysinfoRead();

    if (!(bhyve_driver->config = virBhyveDriverConfigNew()))
        goto cleanup;

    if (virBhyveLoadDriverConfig(bhyve_driver->config, SYSCONFDIR "/libvirt/bhyve.conf") < 0)
        goto cleanup;

    if (g_mkdir_with_parents(BHYVE_LOG_DIR, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %1$s"),
                             BHYVE_LOG_DIR);
        goto cleanup;
    }

    if (g_mkdir_with_parents(BHYVE_STATE_DIR, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %1$s"),
                             BHYVE_STATE_DIR);
        goto cleanup;
    }

    if ((bhyve_driver->lockFD =
         virPidFileAcquire(BHYVE_STATE_DIR, "driver", getpid())) < 0)
        goto cleanup;

    if (virDomainObjListLoadAllConfigs(bhyve_driver->domains,
                                       BHYVE_STATE_DIR,
                                       NULL, true,
                                       bhyve_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    if (virDomainObjListLoadAllConfigs(bhyve_driver->domains,
                                       BHYVE_CONFIG_DIR,
                                       BHYVE_AUTOSTART_DIR, false,
                                       bhyve_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    virBhyveProcessReconnectAll(bhyve_driver);

    if (virDriverShouldAutostart(BHYVE_STATE_DIR, &autostart) < 0)
        goto cleanup;

    if (autostart)
        bhyveAutostartDomains(bhyve_driver);

    return VIR_DRV_STATE_INIT_COMPLETE;

 cleanup:
    bhyveStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
}

unsigned
bhyveDriverGetBhyveCaps(struct _bhyveConn *driver)
{
    if (driver != NULL)
        return driver->bhyvecaps;
    return 0;
}

unsigned
bhyveDriverGetGrubCaps(struct _bhyveConn *driver)
{
    if (driver != NULL)
        return driver->grubcaps;
    return 0;
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

    virReportError(VIR_ERR_INVALID_ARG, _("unknown type '%1$s'"), type);
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
    virCPUDef **cpus = NULL;
    virCPUDef *cpu = NULL;
    char *cpustr = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (virConnectBaselineCPUEnsureACL(conn) < 0)
        goto cleanup;

    if (!(cpus = virCPUDefListParse(xmlCPUs, ncpus, VIR_CPU_TYPE_HOST)))
        goto cleanup;

    if (!(cpu = virCPUBaseline(VIR_ARCH_NONE, cpus, ncpus, NULL, NULL,
                               !!(flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE))))
        goto cleanup;

    if ((flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) &&
        virCPUExpandFeatures(cpus[0]->arch, cpu) < 0)
        goto cleanup;

    cpustr = virCPUDefFormat(cpu, NULL);

 cleanup:
    virCPUDefListFree(cpus);
    virCPUDefFree(cpu);

    return cpustr;
}

static int
bhyveConnectCompareCPU(virConnectPtr conn,
                       const char *xmlDesc,
                       unsigned int flags)
{
    struct _bhyveConn *driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    bool failIncompatible;
    bool validateXML;

    virCheckFlags(VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE |
                  VIR_CONNECT_COMPARE_CPU_VALIDATE_XML,
                  VIR_CPU_COMPARE_ERROR);

    if (virConnectCompareCPUEnsureACL(conn) < 0)
        return VIR_CPU_COMPARE_ERROR;

    failIncompatible = !!(flags & VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE);
    validateXML = !!(flags & VIR_CONNECT_COMPARE_CPU_VALIDATE_XML);

    if (!(caps = bhyveDriverGetCapabilities(driver)))
        return VIR_CPU_COMPARE_ERROR;

    if (!caps->host.cpu ||
        !caps->host.cpu->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("cannot get host CPU capabilities"));
            return VIR_CPU_COMPARE_ERROR;
        }
        VIR_WARN("cannot get host CPU capabilities");
        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    return virCPUCompareXML(caps->host.arch, caps->host.cpu,
                            xmlDesc, failIncompatible, validateXML);
}

static int
bhyveConnectDomainEventRegisterAny(virConnectPtr conn,
                                   virDomainPtr dom,
                                   int eventID,
                                   virConnectDomainEventGenericCallback callback,
                                   void *opaque,
                                   virFreeCallback freecb)
{
    struct _bhyveConn *privconn = conn->privateData;
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
    struct _bhyveConn *privconn = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        privconn->domainEventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}

static int
bhyveDomainHasManagedSaveImage(virDomainPtr domain, unsigned int flags)
{
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainHasManagedSaveImageEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static const char *
bhyveConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "BHYVE";
}

static int bhyveConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

static int
bhyveConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}

static int
bhyveConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
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
    g_autoptr(virDomainDef) def = NULL;
    struct _bhyveConn *privconn = conn->privateData;
    unsigned bhyveCaps = bhyveDriverGetBhyveCaps(privconn);

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        return NULL;

    if (STRNEQ(nativeFormat, BHYVE_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %1$s"), nativeFormat);
        return NULL;
    }

    def = bhyveParseCommandLineString(nativeConfig, bhyveCaps,
                                      privconn->xmlopt);
    if (def == NULL)
        return NULL;

    return virDomainDefFormat(def, privconn->xmlopt, 0);
}

static char *
bhyveConnectGetDomainCapabilities(virConnectPtr conn,
                                  const char *emulatorbin,
                                  const char *arch_str,
                                  const char *machine,
                                  const char *virttype_str,
                                  unsigned int flags)
{
    virDomainCaps *caps = NULL;
    char *ret = NULL;
    int virttype = VIR_DOMAIN_VIRT_BHYVE;
    int arch = virArchFromHost(); /* virArch */

    virCheckFlags(0, ret);

    if (virConnectGetDomainCapabilitiesEnsureACL(conn) < 0)
        return ret;

    if (virttype_str &&
        (virttype = virDomainVirtTypeFromString(virttype_str)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %1$s"),
                       virttype_str);
        goto cleanup;
    }

    if (virttype != VIR_DOMAIN_VIRT_BHYVE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %1$s"),
                       virttype_str);
        goto cleanup;
    }

    if (arch_str && (arch = virArchFromString(arch_str)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown architecture: %1$s"),
                       arch_str);
        goto cleanup;
    }

    if (!ARCH_IS_X86(arch)) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("unsupported architecture: %1$s"),
                       virArchToString(arch));
        goto cleanup;
    }

    if (emulatorbin == NULL)
        emulatorbin = "/usr/sbin/bhyve";

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
    .connectURIProbe = bhyveConnectURIProbe,
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
    .domainDestroyFlags = bhyveDomainDestroyFlags, /* 5.6.0 */
    .domainShutdown = bhyveDomainShutdown, /* 1.3.3 */
    .domainShutdownFlags = bhyveDomainShutdownFlags, /* 5.6.0 */
    .domainReboot = bhyveDomainReboot, /* TBD */
    .domainLookupByUUID = bhyveDomainLookupByUUID, /* 1.2.2 */
    .domainLookupByName = bhyveDomainLookupByName, /* 1.2.2 */
    .domainLookupByID = bhyveDomainLookupByID, /* 1.2.3 */
    .domainDefineXML = bhyveDomainDefineXML, /* 1.2.2 */
    .domainDefineXMLFlags = bhyveDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = bhyveDomainUndefine, /* 1.2.2 */
    .domainUndefineFlags = bhyveDomainUndefineFlags, /* 5.6.0 */
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
    .localOnly = true,
    .uriSchemes = (const char *[]){ "bhyve", NULL },
    .hypervisorDriver = &bhyveHypervisorDriver,
};

static virStateDriver bhyveStateDriver = {
    .name = "bhyve",
    .stateInitialize = bhyveStateInitialize,
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
