/*
 * parallels_driver.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2012 Parallels, Inc.
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/poll.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/statvfs.h>

#include "datatypes.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "vircommand.h"
#include "configmake.h"
#include "virfile.h"
#include "virstoragefile.h"
#include "nodeinfo.h"
#include "virstring.h"
#include "cpu/cpu.h"

#include "parallels_driver.h"
#include "parallels_utils.h"
#include "parallels_sdk.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

VIR_LOG_INIT("parallels.parallels_driver");

#define PRLCTL                      "prlctl"
#define PRLSRVCTL                   "prlsrvctl"

static int parallelsConnectClose(virConnectPtr conn);

void
parallelsDriverLock(parallelsConnPtr driver)
{
    virMutexLock(&driver->lock);
}

void
parallelsDriverUnlock(parallelsConnPtr driver)
{
    virMutexUnlock(&driver->lock);
}

static virCapsPtr
parallelsBuildCapabilities(void)
{
    virCapsPtr caps = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUDataPtr data = NULL;
    virCapsGuestPtr guest;
    virNodeInfo nodeinfo;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    if (nodeCapsInitNUMA(caps) < 0)
        goto error;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm",
                                         VIR_ARCH_X86_64,
                                         "parallels",
                                         NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "parallels", NULL, NULL, 0, NULL) == NULL)
        goto error;

    if ((guest = virCapabilitiesAddGuest(caps, "exe",
                                         VIR_ARCH_X86_64,
                                         "parallels",
                                         NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "parallels", NULL, NULL, 0, NULL) == NULL)
        goto error;

    if (nodeGetInfo(&nodeinfo))
        goto error;

    if (VIR_ALLOC(cpu) < 0)
        goto error;

    cpu->arch = caps->host.arch;
    cpu->type = VIR_CPU_TYPE_HOST;
    cpu->sockets = nodeinfo.sockets;
    cpu->cores = nodeinfo.cores;
    cpu->threads = nodeinfo.threads;

    caps->host.cpu = cpu;

    if (!(data = cpuNodeData(cpu->arch))
        || cpuDecode(cpu, data, NULL, 0, NULL) < 0) {
        goto cleanup;
    }

 cleanup:
    cpuDataFree(data);
    return caps;

 error:
    virObjectUnref(caps);
    goto cleanup;
}

static char *
parallelsConnectGetCapabilities(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    char *xml;

    parallelsDriverLock(privconn);
    xml = virCapabilitiesFormatXML(privconn->caps);
    parallelsDriverUnlock(privconn);
    return xml;
}

static int
parallelsDomainDefPostParse(virDomainDefPtr def ATTRIBUTE_UNUSED,
                            virCapsPtr caps ATTRIBUTE_UNUSED,
                            void *opaque ATTRIBUTE_UNUSED)
{
    return 0;
}


static int
parallelsDomainDeviceDefPostParse(virDomainDeviceDefPtr dev ATTRIBUTE_UNUSED,
                                  const virDomainDef *def ATTRIBUTE_UNUSED,
                                  virCapsPtr caps ATTRIBUTE_UNUSED,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    return 0;
}


virDomainDefParserConfig parallelsDomainDefParserConfig = {
    .macPrefix = {0x42, 0x1C, 0x00},
    .devicesPostParseCallback = parallelsDomainDeviceDefPostParse,
    .domainPostParseCallback = parallelsDomainDefPostParse,
};


static int
parallelsOpenDefault(virConnectPtr conn)
{
    parallelsConnPtr privconn;

    if (VIR_ALLOC(privconn) < 0)
        return VIR_DRV_OPEN_ERROR;
    if (virMutexInit(&privconn->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        goto err_free;
    }

    if (prlsdkInit(privconn)) {
        VIR_DEBUG("%s", _("Can't initialize Parallels SDK"));
        goto err_free;
    }

    if (prlsdkConnect(privconn) < 0)
        goto err_free;

    if (!(privconn->caps = parallelsBuildCapabilities()))
        goto error;

    if (!(privconn->xmlopt = virDomainXMLOptionNew(&parallelsDomainDefParserConfig,
                                                 NULL, NULL)))
        goto error;

    if (!(privconn->domains = virDomainObjListNew()))
        goto error;

    if (!(privconn->domainEventState = virObjectEventStateNew()))
        goto error;

    if (prlsdkSubscribeToPCSEvents(privconn))
        goto error;

    conn->privateData = privconn;

    if (prlsdkLoadDomains(privconn))
        goto error;

    return VIR_DRV_OPEN_SUCCESS;

 error:
    virObjectUnref(privconn->domains);
    virObjectUnref(privconn->caps);
    virStoragePoolObjListFree(&privconn->pools);
    virObjectEventStateFree(privconn->domainEventState);
    prlsdkDisconnect(privconn);
    prlsdkDeinit();
 err_free:
    VIR_FREE(privconn);
    return VIR_DRV_OPEN_ERROR;
}

static virDrvOpenStatus
parallelsConnectOpen(virConnectPtr conn,
                     virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                     unsigned int flags)
{
    int ret;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (!conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (!conn->uri->scheme || STRNEQ(conn->uri->scheme, "parallels"))
        return VIR_DRV_OPEN_DECLINED;

    /* Remote driver should handle these. */
    if (conn->uri->server)
        return VIR_DRV_OPEN_DECLINED;

    /* From this point on, the connection is for us. */
    if (!STREQ_NULLABLE(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected Parallels URI path '%s', try parallels:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if ((ret = parallelsOpenDefault(conn)) != VIR_DRV_OPEN_SUCCESS)
        return ret;

    return VIR_DRV_OPEN_SUCCESS;
}

static int
parallelsConnectClose(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;

    parallelsDriverLock(privconn);
    prlsdkUnsubscribeFromPCSEvents(privconn);
    virObjectUnref(privconn->caps);
    virObjectUnref(privconn->xmlopt);
    virObjectUnref(privconn->domains);
    virObjectEventStateFree(privconn->domainEventState);
    prlsdkDisconnect(privconn);
    conn->privateData = NULL;
    prlsdkDeinit();

    parallelsDriverUnlock(privconn);
    virMutexDestroy(&privconn->lock);

    VIR_FREE(privconn);
    return 0;
}

static int
parallelsConnectGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED, unsigned long *hvVer)
{
    char *output, *sVer, *tmp;
    const char *searchStr = "prlsrvctl version ";
    int ret = -1;

    output = parallelsGetOutput(PRLSRVCTL, "--help", NULL);

    if (!output) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(sVer = strstr(output, searchStr))) {
        parallelsParseError();
        goto cleanup;
    }

    sVer = sVer + strlen(searchStr);

    /* parallels server has versions number like 6.0.17977.782218,
     * so libvirt can handle only first two numbers. */
    if (!(tmp = strchr(sVer, '.'))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(tmp = strchr(tmp + 1, '.'))) {
        parallelsParseError();
        goto cleanup;
    }

    tmp[0] = '\0';
    if (virParseVersionString(sVer, hvVer, true) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(output);
    return ret;
}


static char *parallelsConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return virGetHostname();
}


static int
parallelsConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    parallelsConnPtr privconn = conn->privateData;
    int n;

    parallelsDriverLock(privconn);
    n = virDomainObjListGetActiveIDs(privconn->domains, ids, maxids,
                                     NULL, NULL);
    parallelsDriverUnlock(privconn);

    return n;
}

static int
parallelsConnectNumOfDomains(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int count;

    parallelsDriverLock(privconn);
    count = virDomainObjListNumOfDomains(privconn->domains, true,
                                         NULL, NULL);
    parallelsDriverUnlock(privconn);

    return count;
}

static int
parallelsConnectListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int n;

    parallelsDriverLock(privconn);
    memset(names, 0, sizeof(*names) * maxnames);
    n = virDomainObjListGetInactiveNames(privconn->domains, names,
                                         maxnames, NULL, NULL);
    parallelsDriverUnlock(privconn);

    return n;
}

static int
parallelsConnectNumOfDefinedDomains(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int count;

    parallelsDriverLock(privconn);
    count = virDomainObjListNumOfDomains(privconn->domains, false,
                                         NULL, NULL);
    parallelsDriverUnlock(privconn);

    return count;
}

static int
parallelsConnectListAllDomains(virConnectPtr conn,
                               virDomainPtr **domains,
                               unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);
    parallelsDriverLock(privconn);
    ret = virDomainObjListExport(privconn->domains, conn, domains,
                                 NULL, flags);
    parallelsDriverUnlock(privconn);

    return ret;
}

static virDomainPtr
parallelsDomainLookupByID(virConnectPtr conn, int id)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainObjListFindByID(privconn->domains, id);
    parallelsDriverUnlock(privconn);

    if (dom == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static virDomainPtr
parallelsDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainObjListFindByUUID(privconn->domains, uuid);
    parallelsDriverUnlock(privconn);

    if (dom == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static virDomainPtr
parallelsDomainLookupByName(virConnectPtr conn, const char *name)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainObjListFindByName(privconn->domains, name);
    parallelsDriverUnlock(privconn);

    if (dom == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static int
parallelsDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    info->state = virDomainObjGetState(privdom, NULL);
    info->memory = privdom->def->mem.cur_balloon;
    info->maxMem = privdom->def->mem.max_balloon;
    info->nrVirtCpu = privdom->def->vcpus;
    info->cpuTime = 0;
    ret = 0;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

static char *
parallelsDomainGetOSType(virDomainPtr domain)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;

    char *ret = NULL;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, privdom->def->os.type));

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsDomainIsPersistent(virDomainPtr domain)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    ret = 1;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsDomainGetState(virDomainPtr domain,
                  int *state, int *reason, unsigned int flags)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;
    virCheckFlags(0, -1);

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    *state = virDomainObjGetState(privdom, reason);
    ret = 0;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

static char *
parallelsDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr privdom;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    def = (flags & VIR_DOMAIN_XML_INACTIVE) &&
        privdom->newDef ? privdom->newDef : privdom->def;

    ret = virDomainDefFormat(def, flags);

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

static int
parallelsDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    *autostart = privdom->autostart;
    ret = 0;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

static virDomainPtr
parallelsDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr retdom = NULL;
    virDomainDefPtr def;
    virDomainObjPtr olddom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE;

    parallelsDriverLock(privconn);
    if ((def = virDomainDefParseString(xml, privconn->caps, privconn->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_PARALLELS,
                                       parse_flags)) == NULL)
        goto cleanup;

    olddom = virDomainObjListFindByUUID(privconn->domains, def->uuid);
    if (olddom == NULL) {
        virResetLastError();
        if (STREQ(def->os.type, "hvm")) {
            if (prlsdkCreateVm(conn, def))
                goto cleanup;
        } else if (STREQ(def->os.type, "exe")) {
            if (prlsdkCreateCt(conn, def))
                goto cleanup;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported OS type: %s"), def->os.type);
            goto cleanup;
        }

        olddom = prlsdkAddDomain(privconn, def->uuid);
        if (!olddom)
            goto cleanup;
    } else {
        if (prlsdkApplyConfig(conn, olddom, def))
            goto cleanup;

        if (prlsdkUpdateDomain(privconn, olddom))
            goto cleanup;
    }

    retdom = virGetDomain(conn, def->name, def->uuid);
    if (retdom)
        retdom->id = def->id;

 cleanup:
    if (olddom)
        virObjectUnlock(olddom);
    virDomainDefFree(def);
    parallelsDriverUnlock(privconn);
    return retdom;
}

static virDomainPtr
parallelsDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return parallelsDomainDefineXMLFlags(conn, xml, 0);
}


static int
parallelsNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                     virNodeInfoPtr nodeinfo)
{
    return nodeGetInfo(nodeinfo);
}

static int parallelsConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Encryption is not relevant / applicable to way we talk to PCS */
    return 0;
}

static int parallelsConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* We run CLI tools directly so this is secure */
    return 1;
}

static int parallelsConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}


static char *
parallelsConnectBaselineCPU(virConnectPtr conn ATTRIBUTE_UNUSED,
                            const char **xmlCPUs,
                            unsigned int ncpus,
                            unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, NULL);

    return cpuBaselineXML(xmlCPUs, ncpus, NULL, 0, flags);
}


static int
parallelsDomainGetVcpus(virDomainPtr domain,
                        virVcpuInfoPtr info,
                        int maxinfo,
                        unsigned char *cpumaps,
                        int maplen)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    parallelsDomObjPtr privdomdata = NULL;
    virDomainObjPtr privdom = NULL;
    size_t i;
    int v, maxcpu, hostcpus;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s",
                       _("cannot list vcpu pinning for an inactive domain"));
        goto cleanup;
    }

    privdomdata = privdom->privateData;
    if ((hostcpus = nodeGetCPUCount()) < 0)
        goto cleanup;

    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    if (maxinfo >= 1) {
        if (info != NULL) {
            memset(info, 0, sizeof(*info) * maxinfo);
            for (i = 0; i < maxinfo; i++) {
                info[i].number = i;
                info[i].state = VIR_VCPU_RUNNING;
            }
        }
        if (cpumaps != NULL) {
            unsigned char *tmpmap = NULL;
            int tmpmapLen = 0;

            memset(cpumaps, 0, maplen * maxinfo);
            virBitmapToData(privdomdata->cpumask, &tmpmap, &tmpmapLen);
            if (tmpmapLen > maplen)
                tmpmapLen = maplen;

            for (v = 0; v < maxinfo; v++) {
                unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, v);
                memcpy(cpumap, tmpmap, tmpmapLen);
            }
            VIR_FREE(tmpmap);
        }
    }
    ret = maxinfo;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}


static int
parallelsNodeGetCPUMap(virConnectPtr conn ATTRIBUTE_UNUSED,
                       unsigned char **cpumap,
                       unsigned int *online,
                       unsigned int flags)
{
    return nodeGetCPUMap(cpumap, online, flags);
}

static int
parallelsConnectDomainEventRegisterAny(virConnectPtr conn,
                                       virDomainPtr domain,
                                       int eventID,
                                       virConnectDomainEventGenericCallback callback,
                                       void *opaque,
                                       virFreeCallback freecb)
{
    int ret = -1;
    parallelsConnPtr privconn = conn->privateData;
    if (virDomainEventStateRegisterID(conn,
                                      privconn->domainEventState,
                                      domain, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;
    return ret;
}

static int
parallelsConnectDomainEventDeregisterAny(virConnectPtr conn,
                                         int callbackID)
{
    parallelsConnPtr privconn = conn->privateData;
    int ret = -1;

    if (virObjectEventStateDeregisterID(conn,
                                        privconn->domainEventState,
                                        callbackID) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}

static int parallelsDomainSuspend(virDomainPtr domain)
{
    return prlsdkDomainChangeState(domain, prlsdkPause);
}

static int parallelsDomainResume(virDomainPtr domain)
{
    return prlsdkDomainChangeState(domain, prlsdkResume);
}

static int parallelsDomainCreate(virDomainPtr domain)
{
    return prlsdkDomainChangeState(domain, prlsdkStart);
}

static int parallelsDomainDestroy(virDomainPtr domain)
{
    return prlsdkDomainChangeState(domain, prlsdkKill);
}

static int parallelsDomainShutdown(virDomainPtr domain)
{
    return prlsdkDomainChangeState(domain, prlsdkStop);
}

static int parallelsDomainIsActive(virDomainPtr domain)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr dom = NULL;
    int ret = -1;

    dom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (dom == NULL) {
        parallelsDomNotFoundError(domain);
        return -1;
    }

    ret = virDomainObjIsActive(dom);
    virObjectUnlock(dom);

    return ret;
}

static int
parallelsDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    /* we don't support any create flags */
    virCheckFlags(0, -1);

    return parallelsDomainCreate(domain);
}

static int
parallelsDomainUndefineFlags(virDomainPtr domain,
                             unsigned int flags)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr dom = NULL;

    virCheckFlags(0, -1);

    dom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (dom == NULL) {
        parallelsDomNotFoundError(domain);
        return -1;
    }

    return prlsdkUnregisterDomain(privconn, dom);
}

static int
parallelsDomainUndefine(virDomainPtr domain)
{
    return parallelsDomainUndefineFlags(domain, 0);
}

static virHypervisorDriver parallelsDriver = {
    .no = VIR_DRV_PARALLELS,
    .name = "Parallels",
    .connectOpen = parallelsConnectOpen,            /* 0.10.0 */
    .connectClose = parallelsConnectClose,          /* 0.10.0 */
    .connectGetVersion = parallelsConnectGetVersion,   /* 0.10.0 */
    .connectGetHostname = parallelsConnectGetHostname,      /* 0.10.0 */
    .nodeGetInfo = parallelsNodeGetInfo,      /* 0.10.0 */
    .connectGetCapabilities = parallelsConnectGetCapabilities,      /* 0.10.0 */
    .connectBaselineCPU = parallelsConnectBaselineCPU, /* 1.2.6 */
    .connectListDomains = parallelsConnectListDomains,      /* 0.10.0 */
    .connectNumOfDomains = parallelsConnectNumOfDomains,    /* 0.10.0 */
    .connectListDefinedDomains = parallelsConnectListDefinedDomains,        /* 0.10.0 */
    .connectNumOfDefinedDomains = parallelsConnectNumOfDefinedDomains,      /* 0.10.0 */
    .connectListAllDomains = parallelsConnectListAllDomains, /* 0.10.0 */
    .domainLookupByID = parallelsDomainLookupByID,    /* 0.10.0 */
    .domainLookupByUUID = parallelsDomainLookupByUUID,        /* 0.10.0 */
    .domainLookupByName = parallelsDomainLookupByName,        /* 0.10.0 */
    .domainGetOSType = parallelsDomainGetOSType,    /* 0.10.0 */
    .domainGetInfo = parallelsDomainGetInfo,  /* 0.10.0 */
    .domainGetState = parallelsDomainGetState,        /* 0.10.0 */
    .domainGetXMLDesc = parallelsDomainGetXMLDesc,    /* 0.10.0 */
    .domainIsPersistent = parallelsDomainIsPersistent,        /* 0.10.0 */
    .domainGetAutostart = parallelsDomainGetAutostart,        /* 0.10.0 */
    .domainGetVcpus = parallelsDomainGetVcpus, /* 1.2.6 */
    .domainSuspend = parallelsDomainSuspend,    /* 0.10.0 */
    .domainResume = parallelsDomainResume,    /* 0.10.0 */
    .domainDestroy = parallelsDomainDestroy,  /* 0.10.0 */
    .domainShutdown = parallelsDomainShutdown, /* 0.10.0 */
    .domainCreate = parallelsDomainCreate,    /* 0.10.0 */
    .domainCreateWithFlags = parallelsDomainCreateWithFlags, /* 1.2.10 */
    .domainDefineXML = parallelsDomainDefineXML,      /* 0.10.0 */
    .domainDefineXMLFlags = parallelsDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = parallelsDomainUndefine, /* 1.2.10 */
    .domainUndefineFlags = parallelsDomainUndefineFlags, /* 1.2.10 */
    .domainIsActive = parallelsDomainIsActive, /* 1.2.10 */
    .connectDomainEventRegisterAny = parallelsConnectDomainEventRegisterAny, /* 1.2.10 */
    .connectDomainEventDeregisterAny = parallelsConnectDomainEventDeregisterAny, /* 1.2.10 */
    .nodeGetCPUMap = parallelsNodeGetCPUMap, /* 1.2.8 */
    .connectIsEncrypted = parallelsConnectIsEncrypted, /* 1.2.5 */
    .connectIsSecure = parallelsConnectIsSecure, /* 1.2.5 */
    .connectIsAlive = parallelsConnectIsAlive, /* 1.2.5 */
};

/**
 * parallelsRegister:
 *
 * Registers the parallels driver
 */
int
parallelsRegister(void)
{
    char *prlctl_path;

    prlctl_path = virFindFileInPath(PRLCTL);
    if (!prlctl_path) {
        VIR_DEBUG("%s", _("Can't find prlctl command in the PATH env"));
        return 0;
    }

    VIR_FREE(prlctl_path);

    if (virRegisterHypervisorDriver(&parallelsDriver) < 0)
        return -1;
    if (parallelsStorageRegister())
        return -1;
    if (parallelsNetworkRegister())
        return -1;

    return 0;
}
