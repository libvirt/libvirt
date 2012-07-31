/*
 * parallels_driver.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
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
 * License along with this library;  If not, see
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
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/statvfs.h>

#include "datatypes.h"
#include "virterror_internal.h"
#include "memory.h"
#include "util.h"
#include "logging.h"
#include "command.h"
#include "configmake.h"
#include "storage_file.h"
#include "storage_conf.h"
#include "nodeinfo.h"
#include "json.h"
#include "domain_conf.h"
#include "virdomainlist.h"

#include "parallels_driver.h"
#include "parallels_utils.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

#define PRLCTL                      "prlctl"
#define PRLSRVCTL                   "prlsrvctl"
#define PARALLELS_DEFAULT_ARCH      "x86_64"

#define parallelsDomNotFoundError(domain)                                \
    do {                                                                 \
        char uuidstr[VIR_UUID_STRING_BUFLEN];                            \
        virUUIDFormat(domain->uuid, uuidstr);                            \
        virReportError(VIR_ERR_NO_DOMAIN,                                \
                       _("no domain with matching uuid '%s'"), uuidstr); \
    } while (0)

#define parallelsParseError()                                                  \
    virReportErrorHelper(VIR_FROM_TEST, VIR_ERR_OPERATION_FAILED, __FILE__,    \
                     __FUNCTION__, __LINE__, _("Can't parse prlctl output"))

struct _parallelsConn {
    virMutex lock;
    virDomainObjList domains;
    virStoragePoolObjList pools;
    virCapsPtr caps;
};

typedef struct _parallelsConn parallelsConn;
typedef struct _parallelsConn *parallelsConnPtr;

struct parallelsDomObj {
    int id;
    char *uuid;
    char *os;
};

typedef struct parallelsDomObj *parallelsDomObjPtr;

static int parallelsClose(virConnectPtr conn);

static void
parallelsDriverLock(parallelsConnPtr driver)
{
    virMutexLock(&driver->lock);
}

static void
parallelsDriverUnlock(parallelsConnPtr driver)
{
    virMutexUnlock(&driver->lock);
}

static int
parallelsDefaultConsoleType(const char *ostype ATTRIBUTE_UNUSED)
{
    return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
}

static void
parallelsDomObjFreePrivate(void *p)
{
    parallelsDomObjPtr pdom = p;

    if (!pdom)
        return;

    VIR_FREE(pdom->uuid);
    VIR_FREE(p);
};

static virCapsPtr
parallelsBuildCapabilities(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;
    struct utsname utsname;
    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine, 0, 0)) == NULL)
        goto no_memory;

    if (nodeCapsInitNUMA(caps) < 0)
        goto no_memory;

    virCapabilitiesSetMacPrefix(caps, (unsigned char[]) {
                                0x42, 0x1C, 0x00});

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", PARALLELS_DEFAULT_ARCH,
                                         64, "parallels",
                                         NULL, 0, NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "parallels", NULL, NULL, 0, NULL) == NULL)
        goto no_memory;

    caps->defaultConsoleTargetType = parallelsDefaultConsoleType;
    return caps;

  no_memory:
    virReportOOMError();
    virCapabilitiesFree(caps);
    return NULL;
}

static char *
parallelsGetCapabilities(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    char *xml;

    parallelsDriverLock(privconn);
    if ((xml = virCapabilitiesFormatXML(privconn->caps)) == NULL)
        virReportOOMError();
    parallelsDriverUnlock(privconn);
    return xml;
}

static int
parallelsGetSerialInfo(virDomainChrDefPtr chr,
                       const char *name, virJSONValuePtr value)
{
    const char *tmp;

    chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
    chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    if (virStrToLong_i(name + strlen("serial"),
                       NULL, 10, &chr->target.port) < 0) {
        parallelsParseError();
        return -1;
    }

    if (virJSONValueObjectHasKey(value, "output")) {
        chr->source.type = VIR_DOMAIN_CHR_TYPE_FILE;

        tmp = virJSONValueObjectGetString(value, "output");
        if (!tmp) {
            parallelsParseError();
            return -1;
        }

        if (!(chr->source.data.file.path = strdup(tmp)))
            goto no_memory;
    } else if (virJSONValueObjectHasKey(value, "socket")) {
        chr->source.type = VIR_DOMAIN_CHR_TYPE_UNIX;

        tmp = virJSONValueObjectGetString(value, "socket");
        if (!tmp) {
            parallelsParseError();
            return -1;
        }

        if (!(chr->source.data.nix.path = strdup(tmp)))
            goto no_memory;
        chr->source.data.nix.listen = false;
    } else if (virJSONValueObjectHasKey(value, "real")) {
        chr->source.type = VIR_DOMAIN_CHR_TYPE_DEV;

        tmp = virJSONValueObjectGetString(value, "real");
        if (!tmp) {
            parallelsParseError();
            return -1;
        }

        if (!(chr->source.data.file.path = strdup(tmp)))
            goto no_memory;
    } else {
        parallelsParseError();
        return -1;
    }

    return 0;

  no_memory:
    virReportOOMError();
    return -1;
}

static int
parallelsAddSerialInfo(virDomainDefPtr def,
                       const char *key, virJSONValuePtr value)
{
    virDomainChrDefPtr chr = NULL;

    if (!(chr = virDomainChrDefNew()))
        goto no_memory;

    if (parallelsGetSerialInfo(chr, key, value))
        goto cleanup;

    if (VIR_REALLOC_N(def->serials, def->nserials + 1) < 0)
        goto no_memory;

    def->serials[def->nserials++] = chr;

    return 0;

  no_memory:
    virReportOOMError();
  cleanup:
    virDomainChrDefFree(chr);
    return -1;
}

static int
parallelsAddDomainHardware(virDomainDefPtr def, virJSONValuePtr jobj)
{
    int n;
    size_t i;
    virJSONValuePtr value;
    const char *key;

    n = virJSONValueObjectKeysNumber(jobj);
    if (n < 1)
        goto cleanup;

    for (i = 0; i < n; i++) {
        key = virJSONValueObjectGetKey(jobj, i);
        value = virJSONValueObjectGetValue(jobj, i);

        if (STRPREFIX(key, "serial")) {
            if (parallelsAddSerialInfo(def, key, value))
                goto cleanup;
        }
    }

    return 0;

  cleanup:
    return -1;
}

/*
 * Must be called with privconn->lock held
 */
static virDomainObjPtr
parallelsLoadDomain(parallelsConnPtr privconn, virJSONValuePtr jobj)
{
    virDomainObjPtr dom = NULL;
    virDomainDefPtr def = NULL;
    parallelsDomObjPtr pdom = NULL;
    virJSONValuePtr jobj2, jobj3;
    const char *tmp;
    char *endptr;
    unsigned long mem;
    unsigned int x;
    const char *autostart;
    const char *state;

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    def->virtType = VIR_DOMAIN_VIRT_PARALLELS;
    def->id = -1;

    if (!(tmp = virJSONValueObjectGetString(jobj, "Name"))) {
        parallelsParseError();
        goto cleanup;
    }
    if (!(def->name = strdup(tmp)))
        goto no_memory;

    if (!(tmp = virJSONValueObjectGetString(jobj, "ID"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virUUIDParse(tmp, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("UUID in config file malformed"));
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj, "Description"))) {
        parallelsParseError();
        goto cleanup;
    }
    if (!(def->description = strdup(tmp)))
        goto no_memory;

    if (!(jobj2 = virJSONValueObjectGet(jobj, "Hardware"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(jobj3 = virJSONValueObjectGet(jobj2, "cpu"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virJSONValueObjectGetNumberUint(jobj3, "cpus", &x) < 0) {
        parallelsParseError();
        goto cleanup;
    }
    def->vcpus = x;
    def->maxvcpus = x;

    if (!(jobj3 = virJSONValueObjectGet(jobj2, "memory"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj3, "size"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virStrToLong_ul(tmp, &endptr, 10, &mem) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    if (!STREQ(endptr, "Mb")) {
        parallelsParseError();
        goto cleanup;
    }

    def->mem.max_balloon = mem;
    def->mem.max_balloon <<= 10;
    def->mem.cur_balloon = def->mem.max_balloon;

    if (!(def->os.type = strdup("hvm")))
        goto no_memory;

    if (!(def->os.arch = strdup(PARALLELS_DEFAULT_ARCH)))
        goto no_memory;

    if (VIR_ALLOC(pdom) < 0)
        goto no_memory;

    if (virJSONValueObjectGetNumberUint(jobj, "EnvID", &x) < 0)
        goto cleanup;
    pdom->id = x;
    if (!(tmp = virJSONValueObjectGetString(jobj, "ID"))) {
        parallelsParseError();
        goto cleanup;
    }
    if (!(pdom->uuid = strdup(tmp)))
        goto no_memory;

    if (!(tmp = virJSONValueObjectGetString(jobj, "OS")))
        goto cleanup;

    if (!(state = virJSONValueObjectGetString(jobj, "State"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(autostart = virJSONValueObjectGetString(jobj, "Autostart"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (parallelsAddDomainHardware(def, jobj2) < 0)
        goto cleanup;

    if (!(dom = virDomainAssignDef(privconn->caps,
                                   &privconn->domains, def, false)))
        goto cleanup;
    /* dom is locked here */

    dom->privateDataFreeFunc = parallelsDomObjFreePrivate;
    dom->privateData = pdom;
    dom->persistent = 1;

    /* TODO: handle all possible states */
    if (STREQ(state, "running")) {
        virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_BOOTED);
        def->id = pdom->id;
    }

    if (STREQ(autostart, "on"))
        dom->autostart = 1;
    else
        dom->autostart = 0;

    virDomainObjUnlock(dom);

    return dom;

  no_memory:
    virReportOOMError();
  cleanup:
    virDomainDefFree(def);
    parallelsDomObjFreePrivate(pdom);
    return NULL;
}

/*
 * Must be called with privconn->lock held
 *
 * if domain_name is NULL - load information about all
 * registered domains.
 */
static int
parallelsLoadDomains(parallelsConnPtr privconn, const char *domain_name)
{
    int count, i;
    virJSONValuePtr jobj;
    virJSONValuePtr jobj2;
    virDomainObjPtr dom = NULL;
    int ret = -1;

    jobj = parallelsParseOutput(PRLCTL, "list", "-j", "-a", "-i", "-H",
                                "--vmtype", "vm", domain_name, NULL);
    if (!jobj) {
        parallelsParseError();
        goto cleanup;
    }

    count = virJSONValueArraySize(jobj);
    if (count < 0) {
        parallelsParseError();
        goto cleanup;
    }

    for (i = 0; i < count; i++) {
        jobj2 = virJSONValueArrayGet(jobj, i);
        if (!jobj2) {
            parallelsParseError();
            goto cleanup;
        }

        dom = parallelsLoadDomain(privconn, jobj2);
        if (!dom)
            goto cleanup;
    }

    ret = 0;

  cleanup:
    virJSONValueFree(jobj);
    return ret;
}

static int
parallelsOpenDefault(virConnectPtr conn)
{
    parallelsConnPtr privconn;

    if (VIR_ALLOC(privconn) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&privconn->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        goto error;
    }

    if (!(privconn->caps = parallelsBuildCapabilities()))
        goto error;

    if (virDomainObjListInit(&privconn->domains) < 0)
        goto error;

    conn->privateData = privconn;

    if (parallelsLoadDomains(privconn, NULL))
        goto error;

    return VIR_DRV_OPEN_SUCCESS;

  error:
    virDomainObjListDeinit(&privconn->domains);
    virCapabilitiesFree(privconn->caps);
    virStoragePoolObjListFree(&privconn->pools);
    VIR_FREE(privconn);
    return VIR_DRV_OPEN_ERROR;
}

static virDrvOpenStatus
parallelsOpen(virConnectPtr conn,
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
    if (
        conn->uri->path[0] == '\0' ||
        (conn->uri->path[0] == '/' && conn->uri->path[1] == '\0')) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("parallelsOpen: supply a path or use "
                         "parallels:///session"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (STREQ(conn->uri->path, "/session"))
        ret = parallelsOpenDefault(conn);
    else
        return VIR_DRV_OPEN_DECLINED;

    if (ret != VIR_DRV_OPEN_SUCCESS)
        return ret;

    return VIR_DRV_OPEN_SUCCESS;
}

static int
parallelsClose(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;

    parallelsDriverLock(privconn);
    virCapabilitiesFree(privconn->caps);
    virDomainObjListDeinit(&privconn->domains);
    conn->privateData = NULL;

    parallelsDriverUnlock(privconn);
    virMutexDestroy(&privconn->lock);

    VIR_FREE(privconn);
    return 0;
}

static int
parallelsGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED, unsigned long *hvVer)
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

static int
parallelsListDomains(virConnectPtr conn, int *ids, int maxids)
{
    parallelsConnPtr privconn = conn->privateData;
    int n;

    parallelsDriverLock(privconn);
    n = virDomainObjListGetActiveIDs(&privconn->domains, ids, maxids);
    parallelsDriverUnlock(privconn);

    return n;
}

static int
parallelsNumOfDomains(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int count;

    parallelsDriverLock(privconn);
    count = virDomainObjListNumOfDomains(&privconn->domains, 1);
    parallelsDriverUnlock(privconn);

    return count;
}

static int
parallelsListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int n;

    parallelsDriverLock(privconn);
    memset(names, 0, sizeof(*names) * maxnames);
    n = virDomainObjListGetInactiveNames(&privconn->domains, names,
                                         maxnames);
    parallelsDriverUnlock(privconn);

    return n;
}

static int
parallelsNumOfDefinedDomains(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int count;

    parallelsDriverLock(privconn);
    count = virDomainObjListNumOfDomains(&privconn->domains, 0);
    parallelsDriverUnlock(privconn);

    return count;
}

static int
parallelsListAllDomains(virConnectPtr conn,
                        virDomainPtr **domains,
                        unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_FILTERS_ALL, -1);
    parallelsDriverLock(privconn);
    ret = virDomainList(conn, privconn->domains.objs, domains, flags);
    parallelsDriverUnlock(privconn);

    return ret;
}

static virDomainPtr
parallelsLookupDomainByID(virConnectPtr conn, int id)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainFindByID(&privconn->domains, id);
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
        virDomainObjUnlock(dom);
    return ret;
}

static virDomainPtr
parallelsLookupDomainByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainFindByUUID(&privconn->domains, uuid);
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
        virDomainObjUnlock(dom);
    return ret;
}

static virDomainPtr
parallelsLookupDomainByName(virConnectPtr conn, const char *name)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainFindByName(&privconn->domains, name);
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
        virDomainObjUnlock(dom);
    return ret;
}

static int
parallelsGetDomainInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainFindByUUID(&privconn->domains, domain->uuid);
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
        virDomainObjUnlock(privdom);
    return ret;
}

static char *
parallelsGetOSType(virDomainPtr domain)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;

    char *ret = NULL;

    parallelsDriverLock(privconn);
    privdom = virDomainFindByUUID(&privconn->domains, domain->uuid);
    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    if (!(ret = strdup(privdom->def->os.type)))
        virReportOOMError();

  cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
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
    privdom = virDomainFindByUUID(&privconn->domains, domain->uuid);
    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    ret = 1;

  cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
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
    privdom = virDomainFindByUUID(&privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    *state = virDomainObjGetState(privdom, reason);
    ret = 0;

  cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
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
    privdom = virDomainFindByUUID(&privconn->domains, domain->uuid);
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
        virDomainObjUnlock(privdom);
    return ret;
}

static int
parallelsDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainFindByUUID(&privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    *autostart = privdom->autostart;
    ret = 0;

  cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

typedef int (*parallelsChangeStateFunc)    (virDomainObjPtr privdom);
#define PARALLELS_UUID(x)     (((parallelsDomObjPtr)(x->privateData))->uuid)

static int
parallelsDomainChangeState(virDomainPtr domain,
                           virDomainState req_state, const char *req_state_name,
                           parallelsChangeStateFunc chstate,
                           virDomainState new_state, int reason)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int state;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainFindByUUID(&privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    state = virDomainObjGetState(privdom, NULL);
    if (state != req_state) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("domain '%s' not %s"),
                       privdom->def->name, req_state_name);
        goto cleanup;
    }

    if (chstate(privdom))
        goto cleanup;

    virDomainObjSetState(privdom, new_state, reason);

    ret = 0;

  cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);

    return ret;
}

static int parallelsPause(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "pause", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsPauseDomain(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_RUNNING, "running",
                                      parallelsPause,
                                      VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
}

static int parallelsResume(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "resume", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsResumeDomain(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_PAUSED, "paused",
                                      parallelsResume,
                                      VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);
}

static int parallelsStart(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "start", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsDomainCreate(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_SHUTOFF, "stopped",
                                      parallelsStart,
                                      VIR_DOMAIN_RUNNING, VIR_DOMAIN_EVENT_STARTED_BOOTED);
}

static int parallelsKill(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "stop", PARALLELS_UUID(privdom), "--kill", NULL);
}

static int
parallelsDestroyDomain(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_RUNNING, "running",
                                      parallelsKill,
                                      VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_DESTROYED);
}

static int parallelsStop(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "stop", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsShutdownDomain(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_RUNNING, "running",
                                      parallelsStop,
                                      VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
}

static virDriver parallelsDriver = {
    .no = VIR_DRV_PARALLELS,
    .name = "Parallels",
    .open = parallelsOpen,            /* 0.10.0 */
    .close = parallelsClose,          /* 0.10.0 */
    .version = parallelsGetVersion,   /* 0.10.0 */
    .getHostname = virGetHostname,      /* 0.10.0 */
    .nodeGetInfo = nodeGetInfo,      /* 0.10.0 */
    .getCapabilities = parallelsGetCapabilities,      /* 0.10.0 */
    .listDomains = parallelsListDomains,      /* 0.10.0 */
    .numOfDomains = parallelsNumOfDomains,    /* 0.10.0 */
    .listDefinedDomains = parallelsListDefinedDomains,        /* 0.10.0 */
    .numOfDefinedDomains = parallelsNumOfDefinedDomains,      /* 0.10.0 */
    .listAllDomains = parallelsListAllDomains, /* 0.10.0 */
    .domainLookupByID = parallelsLookupDomainByID,    /* 0.10.0 */
    .domainLookupByUUID = parallelsLookupDomainByUUID,        /* 0.10.0 */
    .domainLookupByName = parallelsLookupDomainByName,        /* 0.10.0 */
    .domainGetOSType = parallelsGetOSType,    /* 0.10.0 */
    .domainGetInfo = parallelsGetDomainInfo,  /* 0.10.0 */
    .domainGetState = parallelsDomainGetState,        /* 0.10.0 */
    .domainGetXMLDesc = parallelsDomainGetXMLDesc,    /* 0.10.0 */
    .domainIsPersistent = parallelsDomainIsPersistent,        /* 0.10.0 */
    .domainGetAutostart = parallelsDomainGetAutostart,        /* 0.10.0 */
    .domainSuspend = parallelsPauseDomain,    /* 0.10.0 */
    .domainResume = parallelsResumeDomain,    /* 0.10.0 */
    .domainDestroy = parallelsDestroyDomain,  /* 0.10.0 */
    .domainShutdown = parallelsShutdownDomain, /* 0.10.0 */
    .domainCreate = parallelsDomainCreate,    /* 0.10.0 */
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

    if (virRegisterDriver(&parallelsDriver) < 0)
        return -1;

    return 0;
}
