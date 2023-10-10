/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_driver.c: Core Cloud-Hypervisor driver functions
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

#include "ch_capabilities.h"
#include "ch_conf.h"
#include "ch_domain.h"
#include "ch_driver.h"
#include "ch_monitor.h"
#include "ch_process.h"
#include "domain_cgroup.h"
#include "datatypes.h"
#include "driver.h"
#include "viraccessapicheck.h"
#include "virchrdev.h"
#include "virerror.h"
#include "virlog.h"
#include "virobject.h"
#include "virtypedparam.h"
#include "virutil.h"
#include "viruuid.h"
#include "virnuma.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_driver");

virCHDriver *ch_driver = NULL;

/* Functions */
static int
chConnectURIProbe(char **uri)
{
    if (ch_driver == NULL)
        return 0;

    *uri = g_strdup("ch:///system");
    return 1;
}

static virDrvOpenStatus chConnectOpen(virConnectPtr conn,
                                      virConnectAuthPtr auth G_GNUC_UNUSED,
                                      virConf *conf G_GNUC_UNUSED,
                                      unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* URI was good, but driver isn't active */
    if (ch_driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Cloud-Hypervisor state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = ch_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int chConnectClose(virConnectPtr conn)
{
    conn->privateData = NULL;
    return 0;
}

static const char *chConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "CH";
}

static int chConnectGetVersion(virConnectPtr conn,
                               unsigned long *version)
{
    virCHDriver *driver = conn->privateData;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    *version = driver->version;
    return 0;
}

static char *chConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static int chConnectNumOfDomains(virConnectPtr conn)
{
    virCHDriver *driver = conn->privateData;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(driver->domains, true,
                                        virConnectNumOfDomainsCheckACL, conn);
}

static int chConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    virCHDriver *driver = conn->privateData;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     virConnectListDomainsCheckACL, conn);
}

static int
chConnectListAllDomains(virConnectPtr conn,
                        virDomainPtr **domains,
                        unsigned int flags)
{
    virCHDriver *driver = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListExport(driver->domains, conn, domains,
                                 virConnectListAllDomainsCheckACL, flags);
}

static int chNodeGetInfo(virConnectPtr conn,
                         virNodeInfoPtr nodeinfo)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return virCapabilitiesGetNodeInfo(nodeinfo);
}

static char *chConnectGetCapabilities(virConnectPtr conn)
{
    virCHDriver *driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    char *xml;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = virCHDriverGetCapabilities(driver, true)))
        return NULL;

    xml = virCapabilitiesFormatXML(caps);

    return xml;
}

/**
 * chDomainCreateXML:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Creates a domain based on xml and starts it
 *
 * Returns a new domain object or NULL in case of failure.
 */
static virDomainPtr
chDomainCreateXML(virConnectPtr conn,
                  const char *xml,
                  unsigned int flags)
{
    virCHDriver *driver = conn->privateData;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;


    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, vmdef) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains,
                                   &vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                       VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virCHProcessStart(driver, vm, VIR_DOMAIN_RUNNING_BOOTED) < 0)
        goto endjob;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    if (vm && !dom) {
        virCHDomainRemoveInactive(driver, vm);
    }
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
chDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    virCHDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    ret = virCHProcessStart(driver, vm, VIR_DOMAIN_RUNNING_BOOTED);

    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainCreate(virDomainPtr dom)
{
    return chDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
chDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    virCHDriver *driver = conn->privateData;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", vmdef->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, vmdef) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, &vmdef,
                                   driver->xmlopt,
                                   0, NULL)))
        goto cleanup;

    vm->persistent = 1;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
chDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return chDomainDefineXMLFlags(conn, xml, 0);
}

static int
chDomainUndefineFlags(virDomainPtr dom,
                      unsigned int flags)
{
    virCHDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUndefineFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Cannot undefine transient domain"));
        goto cleanup;
    }

    vm->persistent = 0;
    if (!virDomainObjIsActive(vm)) {
        virCHDomainRemoveInactive(driver, vm);
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainUndefine(virDomainPtr dom)
{
    return chDomainUndefineFlags(dom, 0);
}

static int chDomainIsActive(virDomainPtr dom)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainShutdownFlags(virDomainPtr dom,
                      unsigned int flags)
{
    virCHDomainObjPrivate *priv;
    virDomainObj *vm;
    virDomainState state;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    state = virDomainObjGetState(vm, NULL);
    if (state != VIR_DOMAIN_RUNNING && state != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("only can shutdown running/paused domain"));
        goto endjob;
    } else {
        if (virCHMonitorShutdownVM(priv->monitor) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to shutdown guest VM"));
            goto endjob;
        }
    }

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTDOWN, VIR_DOMAIN_SHUTDOWN_USER);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainShutdown(virDomainPtr dom)
{
    return chDomainShutdownFlags(dom, 0);
}


static int
chDomainReboot(virDomainPtr dom, unsigned int flags)
{
    virCHDomainObjPrivate *priv;
    virDomainObj *vm;
    virDomainState state;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_REBOOT_ACPI_POWER_BTN, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainRebootEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    state = virDomainObjGetState(vm, NULL);
    if (state != VIR_DOMAIN_RUNNING && state != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("only can reboot running/paused domain"));
        goto endjob;
    } else {
        if (virCHMonitorRebootVM(priv->monitor) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to reboot domain"));
            goto endjob;
        }
    }

    if (state == VIR_DOMAIN_RUNNING)
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    else
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainSuspend(virDomainPtr dom)
{
    virCHDomainObjPrivate *priv;
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("only can suspend running domain"));
        goto endjob;
    } else {
        if (virCHMonitorSuspendVM(priv->monitor) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to suspend domain"));
            goto endjob;
        }
    }

    virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainResume(virDomainPtr dom)
{
    virCHDomainObjPrivate *priv;
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("only can resume paused domain"));
        goto endjob;
    } else {
        if (virCHMonitorResumeVM(priv->monitor) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to resume domain"));
            goto endjob;
        }
    }

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

/**
 * chDomainDestroyFlags:
 * @dom: pointer to domain to destroy
 * @flags: extra flags; not used yet.
 *
 * Sends SIGKILL to Cloud-Hypervisor process to terminate it
 *
 * Returns 0 on success or -1 in case of error
 */
static int
chDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    virCHDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_DESTROY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (virCHProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED) < 0)
        goto endjob;

    virCHDomainRemoveInactive(driver, vm);
    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainDestroy(virDomainPtr dom)
{
    return chDomainDestroyFlags(dom, 0);
}

static virDomainPtr chDomainLookupByID(virConnectPtr conn,
                                       int id)
{
    virCHDriver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(driver->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id '%1$d'"), id);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr chDomainLookupByName(virConnectPtr conn,
                                         const char *name)
{
    virCHDriver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);

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

static virDomainPtr chDomainLookupByUUID(virConnectPtr conn,
                                         const unsigned char *uuid)
{
    virCHDriver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(driver->domains, uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
chDomainGetState(virDomainPtr dom,
                 int *state,
                 int *reason,
                 unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *chDomainGetXMLDesc(virDomainPtr dom,
                                unsigned int flags)
{
    virCHDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, driver->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int chDomainGetInfo(virDomainPtr dom,
                           virDomainInfoPtr info)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(dom->conn, vm->def) < 0)
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
chDomainOpenConsole(virDomainPtr dom,
                    const char *dev_name,
                    virStreamPtr st,
                    unsigned int flags)
{
     virDomainObj *vm = NULL;
     int ret = -1;
     size_t i;
     virDomainChrDef *chr = NULL;
     virCHDomainObjPrivate *priv;

     virCheckFlags(VIR_DOMAIN_CONSOLE_SAFE | VIR_DOMAIN_CONSOLE_FORCE, -1);

     if (!(vm = virCHDomainObjFromDomain(dom)))
          goto cleanup;

     if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
          goto cleanup;

     if (virDomainObjCheckActive(vm) < 0)
          goto cleanup;

     priv = vm->privateData;

     if (dev_name) {
          for (i = 0; !chr && i < vm->def->nconsoles; i++) {
               if (vm->def->consoles[i]->info.alias &&
                   STREQ(dev_name, vm->def->consoles[i]->info.alias))
                    chr = vm->def->consoles[i];
          }
          for (i = 0; !chr && i < vm->def->nserials; i++) {
               if (STREQ(dev_name, vm->def->serials[i]->info.alias))
                    chr = vm->def->serials[i];
          }
     } else {
          if (vm->def->nconsoles &&
              vm->def->consoles[0]->source->type == VIR_DOMAIN_CHR_TYPE_PTY)
               chr = vm->def->consoles[0];
          else if (vm->def->nserials &&
                   vm->def->serials[0]->source->type == VIR_DOMAIN_CHR_TYPE_PTY)
               chr = vm->def->serials[0];
     }

     if (!chr) {
          virReportError(VIR_ERR_INTERNAL_ERROR, _("cannot find character device %1$s"),
                         NULLSTR(dev_name));
          goto cleanup;
     }

     if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
          virReportError(VIR_ERR_INTERNAL_ERROR,
                         _("character device %1$s is not using a PTY"),
                         dev_name ? dev_name : NULLSTR(chr->info.alias));
          goto cleanup;
     }

     /* handle mutually exclusive access to console devices */
     ret = virChrdevOpen(priv->chrdevs, chr->source, st,
                         (flags & VIR_DOMAIN_CONSOLE_FORCE) != 0);

     if (ret == 1) {
          virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                         _("Active console session exists for this domain"));
          ret = -1;
     }

 cleanup:
     virDomainObjEndAPI(&vm);
     return ret;
}

static int chStateCleanup(void)
{
    if (ch_driver == NULL)
        return -1;

    virObjectUnref(ch_driver->domains);
    virObjectUnref(ch_driver->xmlopt);
    virObjectUnref(ch_driver->caps);
    virObjectUnref(ch_driver->config);
    virMutexDestroy(&ch_driver->lock);
    g_clear_pointer(&ch_driver, g_free);

    return 0;
}

static int chStateInitialize(bool privileged,
                             const char *root,
                             bool monolithic G_GNUC_UNUSED,
                             virStateInhibitCallback callback G_GNUC_UNUSED,
                             void *opaque G_GNUC_UNUSED)
{
    int ret = VIR_DRV_STATE_INIT_ERROR;
    int rv;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    ch_driver = g_new0(virCHDriver, 1);

    if (virMutexInit(&ch_driver->lock) < 0) {
        g_free(ch_driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    if (!(ch_driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(ch_driver->caps = virCHDriverCapsInit()))
        goto cleanup;

    if (!(ch_driver->xmlopt = chDomainXMLConfInit(ch_driver)))
        goto cleanup;

    if (!(ch_driver->config = virCHDriverConfigNew(privileged)))
        goto cleanup;

    if ((rv = chExtractVersion(ch_driver)) < 0) {
        if (rv == -2)
            ret = VIR_DRV_STATE_INIT_SKIPPED;
        goto cleanup;
    }

    ch_driver->chCaps = virCHCapsInitCHVersionCaps(ch_driver->version);

    ch_driver->privileged = privileged;
    ret = VIR_DRV_STATE_INIT_COMPLETE;

 cleanup:
    if (ret != VIR_DRV_STATE_INIT_COMPLETE)
        chStateCleanup();
    return ret;
}

/* Which features are supported by this driver? */
static int
chConnectSupportsFeature(virConnectPtr conn,
                         int feature)
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
        case VIR_DRV_FEATURE_MIGRATION_V2:
        case VIR_DRV_FEATURE_MIGRATION_V3:
        case VIR_DRV_FEATURE_MIGRATION_P2P:
        case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
        case VIR_DRV_FEATURE_XML_MIGRATABLE:
        case VIR_DRV_FEATURE_MIGRATION_OFFLINE:
        case VIR_DRV_FEATURE_MIGRATION_PARAMS:
        case VIR_DRV_FEATURE_MIGRATION_DIRECT:
        case VIR_DRV_FEATURE_MIGRATION_V1:
        default:
            return 0;
    }
}

static int
chDomainGetVcpusFlags(virDomainPtr dom,
                      unsigned int flags)
{
    virDomainObj *vm;
    virDomainDef *def;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_GUEST, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        return -1;

    if (virDomainGetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if (flags & VIR_DOMAIN_VCPU_MAXIMUM)
        ret = virDomainDefGetVcpusMax(def);
    else
        ret = virDomainDefGetVcpus(def);


 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainGetMaxVcpus(virDomainPtr dom)
{
    return chDomainGetVcpusFlags(dom,
                                 (VIR_DOMAIN_AFFECT_LIVE |
                                  VIR_DOMAIN_VCPU_MAXIMUM));
}

static int
chDomainGetVcpuPinInfo(virDomain *dom,
                       int ncpumaps,
                       unsigned char *cpumaps,
                       int maplen,
                       unsigned int flags)
{
    virDomainObj *vm = NULL;
    virDomainDef *def;
    bool live;
    int ret = -1;

    g_autoptr(virBitmap) hostcpus = NULL;
    virBitmap *autoCpuset = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpuPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDefState(vm, flags, &live)))
        goto cleanup;

    if (!(hostcpus = virHostCPUGetAvailableCPUsBitmap()))
        goto cleanup;

    if (live)
        autoCpuset = CH_DOMAIN_PRIVATE(vm)->autoCpuset;

    ret = virDomainDefGetVcpuPinInfoHelper(def, maplen, ncpumaps, cpumaps,
                                           hostcpus, autoCpuset);
 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chNodeGetCPUMap(virConnectPtr conn,
                unsigned char **cpumap,
                unsigned int *online, unsigned int flags)
{
    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    return virHostCPUGetMap(cpumap, online, flags);
}


static int
chDomainHelperGetVcpus(virDomainObj *vm,
                       virVcpuInfoPtr info,
                       unsigned long long *cpuwait,
                       int maxinfo,
                       unsigned char *cpumaps,
                       int maplen)
{
    size_t ncpuinfo = 0;
    size_t i;

    if (maxinfo == 0)
        return 0;

    if (!virCHDomainHasVcpuPids(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cpu affinity is not supported"));
        return -1;
    }

    if (info)
        memset(info, 0, sizeof(*info) * maxinfo);

    if (cpumaps)
        memset(cpumaps, 0, sizeof(*cpumaps) * maxinfo);

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def) && ncpuinfo < maxinfo; i++) {
        virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, i);
        pid_t vcpupid = virCHDomainGetVcpuPid(vm, i);
        virVcpuInfoPtr vcpuinfo = info + ncpuinfo;

        if (!vcpu->online)
            continue;

        if (info) {
            vcpuinfo->number = i;
            vcpuinfo->state = VIR_VCPU_RUNNING;
            if (virProcessGetStatInfo(&vcpuinfo->cpuTime,
                                      NULL, NULL,
                                      &vcpuinfo->cpu, NULL,
                                      vm->pid, vcpupid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot get vCPU placement & pCPU time"));
                return -1;
            }
        }

        if (cpumaps) {
            unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, ncpuinfo);
            g_autoptr(virBitmap) map = NULL;

            if (!(map = virProcessGetAffinity(vcpupid)))
                return -1;

            virBitmapToDataBuf(map, cpumap, maplen);
        }

        if (cpuwait) {
            if (virProcessGetSchedInfo(&(cpuwait[ncpuinfo]), vm->pid, vcpupid) < 0)
                return -1;
        }

        ncpuinfo++;
    }

    return ncpuinfo;
}

static int
chDomainGetVcpus(virDomainPtr dom,
                 virVcpuInfoPtr info,
                 int maxinfo,
                 unsigned char *cpumaps,
                 int maplen)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpusEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot retrieve vcpu information for inactive domain"));
        goto cleanup;
    }

    ret = chDomainHelperGetVcpus(vm, info, NULL, maxinfo, cpumaps, maplen);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainPinVcpuLive(virDomainObj *vm,
                    virDomainDef *def,
                    int vcpu,
                    virCHDriver *driver,
                    virCHDriverConfig *cfg,
                    virBitmap *cpumap)
{
    g_autoptr(virBitmap) tmpmap = NULL;
    g_autoptr(virCgroup) cgroup_vcpu = NULL;
    virDomainVcpuDef *vcpuinfo;
    virCHDomainObjPrivate *priv = vm->privateData;

    if (!virCHDomainHasVcpuPids(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cpu affinity is not supported"));
        return -1;
    }

    if (!(vcpuinfo = virDomainDefGetVcpu(def, vcpu))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("vcpu %1$d is out of range of live cpu count %2$d"),
                       vcpu, virDomainDefGetVcpusMax(def));
        return -1;
    }

    if (!(tmpmap = virBitmapNewCopy(cpumap)))
        return -1;

    if (vcpuinfo->online) {
        /* Configure the corresponding cpuset cgroup before set affinity. */
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, vcpu,
                                   false, &cgroup_vcpu) < 0)
                return -1;
            if (virDomainCgroupSetupCpusetCpus(cgroup_vcpu, cpumap) < 0)
                return -1;
        }

        if (virProcessSetAffinity(virCHDomainGetVcpuPid(vm, vcpu), cpumap, false) < 0)
            return -1;
    }

    virBitmapFree(vcpuinfo->cpumask);
    vcpuinfo->cpumask = g_steal_pointer(&tmpmap);

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        return -1;

    return 0;
}

static int
chDomainPinVcpuFlags(virDomainPtr dom,
                     unsigned int vcpu,
                     unsigned char *cpumap,
                     int maplen,
                     unsigned int flags)
{
    virCHDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virDomainDef *def;
    virDomainDef *persistentDef;
    int ret = -1;
    g_autoptr(virBitmap) pcpumap = NULL;
    virDomainVcpuDef *vcpuinfo = NULL;
    g_autoptr(virCHDriverConfig) cfg = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virCHDriverGetConfig(driver);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinVcpuFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (persistentDef &&
        !(vcpuinfo = virDomainDefGetVcpu(persistentDef, vcpu))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("vcpu %1$d is out of range of persistent cpu count %2$d"),
                       vcpu, virDomainDefGetVcpus(persistentDef));
        goto endjob;
    }

    if (!(pcpumap = virBitmapNewData(cpumap, maplen)))
        goto endjob;

    if (virBitmapIsAllClear(pcpumap)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Empty cpu list for pinning"));
        goto endjob;
    }

    if (def &&
        chDomainPinVcpuLive(vm, def, vcpu, driver, cfg, pcpumap) < 0)
        goto endjob;

    if (persistentDef) {
        virBitmapFree(vcpuinfo->cpumask);
        vcpuinfo->cpumask = g_steal_pointer(&pcpumap);
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
chDomainPinVcpu(virDomainPtr dom,
                unsigned int vcpu,
                unsigned char *cpumap,
                int maplen)
{
    return chDomainPinVcpuFlags(dom, vcpu, cpumap, maplen,
                                VIR_DOMAIN_AFFECT_LIVE);
}



static int
chDomainGetEmulatorPinInfo(virDomainPtr dom,
                           unsigned char *cpumaps,
                           int maplen,
                           unsigned int flags)
{
    virDomainObj *vm = NULL;
    virDomainDef *def;
    virCHDomainObjPrivate *priv;
    bool live;
    int ret = -1;
    virBitmap *cpumask = NULL;
    g_autoptr(virBitmap) bitmap = NULL;
    virBitmap *autoCpuset = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetEmulatorPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDefState(vm, flags, &live)))
        goto cleanup;

    if (live) {
        priv = vm->privateData;
        autoCpuset = priv->autoCpuset;
    }
    if (def->cputune.emulatorpin) {
        cpumask = def->cputune.emulatorpin;
    } else if (def->cpumask) {
        cpumask = def->cpumask;
    } else if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
               autoCpuset) {
        cpumask = autoCpuset;
    } else {
        if (!(bitmap = virHostCPUGetAvailableCPUsBitmap()))
            goto cleanup;
        cpumask = bitmap;
    }

    virBitmapToDataBuf(cpumask, cpumaps, maplen);

    ret = 1;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainPinEmulator(virDomainPtr dom,
                    unsigned char *cpumap,
                    int maplen,
                    unsigned int flags)
{
    virCHDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virDomainDef *def;
    virDomainDef *persistentDef;
    int ret = -1;
    virCHDomainObjPrivate *priv;
    g_autoptr(virBitmap) pcpumap = NULL;
    g_autoptr(virCHDriverConfig) cfg = NULL;
    virTypedParameterPtr eventParams = NULL;
    int eventNparams = 0;
    int eventMaxparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virCHDriverGetConfig(driver);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinEmulatorEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    priv = vm->privateData;

    if (!(pcpumap = virBitmapNewData(cpumap, maplen)))
        goto endjob;

    if (virBitmapIsAllClear(pcpumap)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Empty cpu list for pinning"));
        goto endjob;
    }

    if (def) {
        g_autoptr(virCgroup) cgroup_emulator = NULL;
        g_autofree char *str = NULL;

        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR,
                                   0, false, &cgroup_emulator) < 0)
                goto endjob;

            if (virDomainCgroupSetupCpusetCpus(cgroup_emulator, pcpumap) < 0) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("failed to set cpuset.cpus in cgroup for emulator threads"));
                goto endjob;
            }
        }

        if (virProcessSetAffinity(vm->pid, pcpumap, false) < 0)
            goto endjob;

        g_clear_pointer(&def->cputune.emulatorpin, virBitmapFree);

        if (!(def->cputune.emulatorpin = virBitmapNewCopy(pcpumap)))
            goto endjob;

        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
            goto endjob;

        str = virBitmapFormat(pcpumap);
        if (virTypedParamsAddString(&eventParams, &eventNparams,
                                    &eventMaxparams,
                                    VIR_DOMAIN_TUNABLE_CPU_EMULATORPIN,
                                    str) < 0)
            goto endjob;
    }

    if (persistentDef) {
        virBitmapFree(persistentDef->cputune.emulatorpin);
        persistentDef->cputune.emulatorpin = virBitmapNewCopy(pcpumap);

        /* Inactive XMLs are not saved, yet. */
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

#define CH_NB_NUMA_PARAM 2

static int
chDomainGetNumaParameters(virDomainPtr dom,
                          virTypedParameterPtr params,
                          int *nparams,
                          unsigned int flags)
{
    size_t i;
    virDomainObj *vm = NULL;
    virDomainNumatuneMemMode tmpmode = VIR_DOMAIN_NUMATUNE_MEM_STRICT;
    virCHDomainObjPrivate *priv;
    g_autofree char *nodeset = NULL;
    int ret = -1;
    virDomainDef *def = NULL;
    bool live = false;
    virBitmap *autoNodeset = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = virCHDomainObjFromDomain(dom)))
        return -1;
    priv = vm->privateData;

    if (virDomainGetNumaParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDefState(vm, flags, &live)))
        goto cleanup;

    if (live)
        autoNodeset = priv->autoNodeset;

    if ((*nparams) == 0) {
        *nparams = CH_NB_NUMA_PARAM;
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < CH_NB_NUMA_PARAM && i < *nparams; i++) {
        virMemoryParameterPtr param = &params[i];

        switch (i) {
        case 0: /* fill numa mode here */
            ignore_value(virDomainNumatuneGetMode(def->numa, -1, &tmpmode));

            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_MODE,
                                        VIR_TYPED_PARAM_INT, tmpmode) < 0)
                goto cleanup;

            break;

        case 1: /* fill numa nodeset here */
            nodeset = virDomainNumatuneFormatNodeset(def->numa, autoNodeset, -1);

            if (!nodeset ||
                virTypedParameterAssign(param, VIR_DOMAIN_NUMA_NODESET,
                                        VIR_TYPED_PARAM_STRING, nodeset) < 0)
                goto cleanup;

            nodeset = NULL;
            break;

        default:
            break;
            /* should not hit here */
        }
    }

    if (*nparams > CH_NB_NUMA_PARAM)
        *nparams = CH_NB_NUMA_PARAM;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
chDomainSetNumaParamsLive(virDomainObj *vm,
                          virBitmap *nodeset)
{
    g_autoptr(virCgroup) cgroup_temp = NULL;
    virCHDomainObjPrivate *priv = vm->privateData;
    g_autofree char *nodeset_str = NULL;
    virDomainNumatuneMemMode mode;
    size_t i = 0;

    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mode) == 0 &&
        mode != VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("change of nodeset for running domain requires strict numa mode"));
        return -1;
    }

    if (!virNumaNodesetIsAvailable(nodeset))
        return -1;

    /* Ensure the cpuset string is formatted before passing to cgroup */
    if (!(nodeset_str = virBitmapFormat(nodeset)))
        return -1;

    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &cgroup_temp) < 0 ||
        virCgroupSetCpusetMems(cgroup_temp, nodeset_str) < 0)
        return -1;


    for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
        virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, i);

        if (!vcpu->online)
            continue;

        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, i,
                               false, &cgroup_temp) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, nodeset_str) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->niothreadids; i++) {
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_IOTHREAD,
                               vm->def->iothreadids[i]->iothread_id,
                               false, &cgroup_temp) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, nodeset_str) < 0)
            return -1;
    }

    /* set nodeset for root cgroup */
    if (virCgroupSetCpusetMems(priv->cgroup, nodeset_str) < 0)
        return -1;

    return 0;
}

static int
chDomainSetNumaParameters(virDomainPtr dom,
                          virTypedParameterPtr params,
                          int nparams,
                          unsigned int flags)
{
    virCHDriver *driver = dom->conn->privateData;
    size_t i;
    virDomainDef *def;
    virDomainDef *persistentDef;
    virDomainObj *vm = NULL;
    int ret = -1;
    g_autoptr(virCHDriverConfig) cfg = NULL;
    virCHDomainObjPrivate *priv;
    g_autoptr(virBitmap) nodeset = NULL;
    virDomainNumatuneMemMode config_mode;
    int mode = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_NUMA_MODE,
                               VIR_TYPED_PARAM_INT,
                               VIR_DOMAIN_NUMA_NODESET,
                               VIR_TYPED_PARAM_STRING,
                               NULL) < 0)
        return -1;

    if (!(vm = virCHDomainObjFromDomain(dom)))
        return -1;

    if (virDomainSetNumaParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    priv = vm->privateData;
    cfg = virCHDriverGetConfig(driver);

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_NUMA_MODE)) {
            mode = param->value.i;

            if (mode < 0 || mode >= VIR_DOMAIN_NUMATUNE_MEM_LAST) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("unsupported numatune mode: '%1$d'"), mode);
                goto cleanup;
            }

        } else if (STREQ(param->field, VIR_DOMAIN_NUMA_NODESET)) {
            if (virBitmapParse(param->value.s, &nodeset,
                               VIR_DOMAIN_CPUMASK_LEN) < 0)
                goto cleanup;

            if (virBitmapIsAllClear(nodeset)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("Invalid nodeset of 'numatune': %1$s"),
                               param->value.s);
                goto cleanup;
            }
        }
    }

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (def) {
        if (!driver->privileged) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("NUMA tuning is not available in session mode"));
            goto endjob;
        }

        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cgroup cpuset controller is not mounted"));
            goto endjob;
        }

        if (mode != -1 &&
            virDomainNumatuneGetMode(def->numa, -1, &config_mode) == 0 &&
            config_mode != mode) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("can't change numatune mode for running domain"));
            goto endjob;
        }

        if (nodeset &&
            chDomainSetNumaParamsLive(vm, nodeset) < 0)
            goto endjob;

        if (virDomainNumatuneSet(def->numa,
                                 def->placement_mode ==
                                 VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                 -1, mode, nodeset) < 0)
            goto endjob;

        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
            goto endjob;
    }

    if (persistentDef) {
        if (virDomainNumatuneSet(persistentDef->numa,
                                 persistentDef->placement_mode ==
                                 VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                 -1, mode, nodeset) < 0)
            goto endjob;

        /* Inactive XMLs are not saved, yet. */
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

/* Function Tables */
static virHypervisorDriver chHypervisorDriver = {
    .name = "CH",
    .connectURIProbe = chConnectURIProbe,
    .connectOpen = chConnectOpen,                           /* 7.5.0 */
    .connectClose = chConnectClose,                         /* 7.5.0 */
    .connectGetType = chConnectGetType,                     /* 7.5.0 */
    .connectGetVersion = chConnectGetVersion,               /* 7.5.0 */
    .connectGetHostname = chConnectGetHostname,             /* 7.5.0 */
    .connectNumOfDomains = chConnectNumOfDomains,           /* 7.5.0 */
    .connectListAllDomains = chConnectListAllDomains,       /* 7.5.0 */
    .connectListDomains = chConnectListDomains,             /* 7.5.0 */
    .connectGetCapabilities = chConnectGetCapabilities,     /* 7.5.0 */
    .connectSupportsFeature = chConnectSupportsFeature,     /* 8.1.0 */
    .domainCreateXML = chDomainCreateXML,                   /* 7.5.0 */
    .domainCreate = chDomainCreate,                         /* 7.5.0 */
    .domainCreateWithFlags = chDomainCreateWithFlags,       /* 7.5.0 */
    .domainShutdown = chDomainShutdown,                     /* 7.5.0 */
    .domainShutdownFlags = chDomainShutdownFlags,           /* 7.5.0 */
    .domainReboot = chDomainReboot,                         /* 7.5.0 */
    .domainSuspend = chDomainSuspend,                       /* 7.5.0 */
    .domainResume = chDomainResume,                         /* 7.5.0 */
    .domainDestroy = chDomainDestroy,                       /* 7.5.0 */
    .domainDestroyFlags = chDomainDestroyFlags,             /* 7.5.0 */
    .domainDefineXML = chDomainDefineXML,                   /* 7.5.0 */
    .domainDefineXMLFlags = chDomainDefineXMLFlags,         /* 7.5.0 */
    .domainUndefine = chDomainUndefine,                     /* 7.5.0 */
    .domainUndefineFlags = chDomainUndefineFlags,           /* 7.5.0 */
    .domainLookupByID = chDomainLookupByID,                 /* 7.5.0 */
    .domainLookupByUUID = chDomainLookupByUUID,             /* 7.5.0 */
    .domainLookupByName = chDomainLookupByName,             /* 7.5.0 */
    .domainGetState = chDomainGetState,                     /* 7.5.0 */
    .domainGetXMLDesc = chDomainGetXMLDesc,                 /* 7.5.0 */
    .domainGetInfo = chDomainGetInfo,                       /* 7.5.0 */
    .domainIsActive = chDomainIsActive,                     /* 7.5.0 */
    .domainOpenConsole = chDomainOpenConsole,               /* 7.8.0 */
    .nodeGetInfo = chNodeGetInfo,                           /* 7.5.0 */
    .domainGetVcpus = chDomainGetVcpus,                     /* 8.0.0 */
    .domainGetVcpusFlags = chDomainGetVcpusFlags,           /* 8.0.0 */
    .domainGetMaxVcpus = chDomainGetMaxVcpus,               /* 8.0.0 */
    .domainGetVcpuPinInfo = chDomainGetVcpuPinInfo,         /* 8.0.0 */
    .domainPinVcpu = chDomainPinVcpu,                       /* 8.1.0 */
    .domainPinVcpuFlags = chDomainPinVcpuFlags,             /* 8.1.0 */
    .domainPinEmulator = chDomainPinEmulator,               /* 8.1.0 */
    .domainGetEmulatorPinInfo = chDomainGetEmulatorPinInfo, /* 8.1.0 */
    .nodeGetCPUMap = chNodeGetCPUMap,                       /* 8.0.0 */
    .domainSetNumaParameters = chDomainSetNumaParameters,   /* 8.1.0 */
    .domainGetNumaParameters = chDomainGetNumaParameters,   /* 8.1.0 */
};

static virConnectDriver chConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){"ch", NULL},
    .hypervisorDriver = &chHypervisorDriver,
};

static virStateDriver chStateDriver = {
    .name = "cloud-hypervisor",
    .stateInitialize = chStateInitialize,
    .stateCleanup = chStateCleanup,
};

int chRegister(void)
{
    if (virRegisterConnectDriver(&chConnectDriver, true) < 0)
        return -1;
    if (virRegisterStateDriver(&chStateDriver) < 0)
        return -1;
    return 0;
}
