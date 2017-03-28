/*
 * openvz_driver.c: core driver methods for managing OpenVZ VEs
 *
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
 * Copyright (C) 2007 Anoop Joe Cyriac
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
 * Authors:
 * Shuveb Hussain <shuveb@binarykarma.com>
 * Anoop Joe Cyriac <anoop@binarykarma.com>
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
#include <pwd.h>
#include <sys/wait.h>

#include "virerror.h"
#include "datatypes.h"
#include "openvz_driver.h"
#include "openvz_util.h"
#include "virbuffer.h"
#include "openvz_conf.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virlog.h"
#include "vircommand.h"
#include "viruri.h"
#include "virnetdevtap.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_OPENVZ

VIR_LOG_INIT("openvz.openvz_driver");

#define OPENVZ_NB_MEM_PARAM 3

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid);
static int openvzConnectGetMaxVcpus(virConnectPtr conn, const char *type);
static int openvzDomainGetMaxVcpus(virDomainPtr dom);
static int openvzDomainSetVcpusInternal(virDomainObjPtr vm,
                                        unsigned int nvcpus,
                                        virDomainXMLOptionPtr xmlopt);
static int openvzDomainSetMemoryInternal(virDomainObjPtr vm,
                                         unsigned long long memory);
static int openvzGetVEStatus(virDomainObjPtr vm, int *status, int *reason);

static void openvzDriverLock(struct openvz_driver *driver)
{
    virMutexLock(&driver->lock);
}

static void openvzDriverUnlock(struct openvz_driver *driver)
{
    virMutexUnlock(&driver->lock);
}

struct openvz_driver ovz_driver;

static int
openvzDomainDefPostParse(virDomainDefPtr def,
                         virCapsPtr caps ATTRIBUTE_UNUSED,
                         unsigned int parseFlags ATTRIBUTE_UNUSED,
                         void *opaque ATTRIBUTE_UNUSED,
                         void *parseOpaque ATTRIBUTE_UNUSED)
{
    /* fill the init path */
    if (def->os.type == VIR_DOMAIN_OSTYPE_EXE && !def->os.init) {
        if (VIR_STRDUP(def->os.init, "/sbin/init") < 0)
            return -1;
    }

    return 0;
}


static int
openvzDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                               const virDomainDef *def ATTRIBUTE_UNUSED,
                               virCapsPtr caps ATTRIBUTE_UNUSED,
                               unsigned int parseFlags ATTRIBUTE_UNUSED,
                               void *opaque ATTRIBUTE_UNUSED,
                               void *parseOpaque ATTRIBUTE_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE)
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_OPENVZ;

    /* forbid capabilities mode hostdev in this kind of hypervisor */
    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode 'capabilities' is not "
                         "supported in %s"),
                       virDomainVirtTypeToString(def->virtType));
        return -1;
    }

    return 0;
}


virDomainDefParserConfig openvzDomainDefParserConfig = {
    .domainPostParseCallback = openvzDomainDefPostParse,
    .devicesPostParseCallback = openvzDomainDeviceDefPostParse,
    .features = VIR_DOMAIN_DEF_FEATURE_NAME_SLASH,
};


/* generate arguments to create OpenVZ container
   return -1 - error
           0 - OK
   Caller has to free the cmd
*/
static virCommandPtr
openvzDomainDefineCmd(virDomainDefPtr vmdef)
{
    virCommandPtr cmd = virCommandNewArgList(VZCTL,
                                             "--quiet",
                                             "create",
                                             NULL);

    if (vmdef == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Container is not defined"));
        virCommandFree(cmd);
        return NULL;
    }

    virCommandAddArgList(cmd, vmdef->name, "--name", vmdef->name, NULL);

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_TEMPLATE) {
        virCommandAddArgList(cmd, "--ostemplate", vmdef->fss[0]->src, NULL);
    }

    return cmd;
}


static int openvzSetInitialConfig(virDomainDefPtr vmdef)
{
    int ret = -1;
    int vpsid;
    char * confdir = NULL;
    virCommandPtr cmd = NULL;

    if (vmdef->nfss > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only one filesystem supported"));
        goto cleanup;
    }

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_TEMPLATE &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("filesystem is not of type 'template' or 'mount'"));
        goto cleanup;
    }


    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_MOUNT)
    {

        if (virStrToLong_i(vmdef->name, NULL, 10, &vpsid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not convert domain name to VEID"));
            goto cleanup;
        }

        if (openvzCopyDefaultConfig(vpsid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not copy default config"));
            goto cleanup;
        }

        if (openvzWriteVPSConfigParam(vpsid, "VE_PRIVATE", vmdef->fss[0]->src->path) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set the source dir for the filesystem"));
            goto cleanup;
        }
    } else {
        cmd = openvzDomainDefineCmd(vmdef);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
  VIR_FREE(confdir);
  virCommandFree(cmd);

  return ret;
}


static int
openvzSetDiskQuota(virDomainDefPtr vmdef,
                   virDomainFSDefPtr fss,
                   bool persist)
{
    int ret = -1;
    unsigned long long sl, hl;
    virCommandPtr cmd = virCommandNewArgList(VZCTL,
                                             "--quiet",
                                             "set",
                                             vmdef->name,
                                             NULL);
    if (persist)
        virCommandAddArg(cmd, "--save");

    if (fss->type == VIR_DOMAIN_FS_TYPE_TEMPLATE) {
        if (fss->space_hard_limit) {
            hl = VIR_DIV_UP(fss->space_hard_limit, 1024);
            virCommandAddArg(cmd, "--diskspace");

            if (fss->space_soft_limit) {
                sl = VIR_DIV_UP(fss->space_soft_limit, 1024);
                virCommandAddArgFormat(cmd, "%lld:%lld", sl, hl);
            } else {
                virCommandAddArgFormat(cmd, "%lld", hl);
            }
        } else if (fss->space_soft_limit) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Can't set soft limit without hard limit"));
            goto cleanup;
        }

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
  virCommandFree(cmd);

  return ret;
}


static char *
openvzDomainGetHostname(virDomainPtr dom, unsigned int flags)
{
    char *hostname = NULL;
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;

    virCheckFlags(0, NULL);
    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    hostname = openvzVEGetStringParam(dom, "hostname");
    if (hostname == NULL)
        goto error;

    /* vzlist prints an unset hostname as '-' */
    if (STREQ(hostname, "-")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Hostname of '%s' is unset"), vm->def->name);
        goto error;
    }

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return hostname;

 error:
    VIR_FREE(hostname);
    goto cleanup;
}


static virDomainPtr openvzDomainLookupByID(virConnectPtr conn,
                                           int id)
{
    struct openvz_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByID(driver->domains, id);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static int openvzConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct  openvz_driver *driver = conn->privateData;
    openvzDriverLock(driver);
    *version = driver->version;
    openvzDriverUnlock(driver);
    return 0;
}


static char *openvzConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return virGetHostname();
}


static char *openvzDomainGetOSType(virDomainPtr dom)
{
    struct  openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, virDomainOSTypeToString(vm->def->os.type)));

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid)
{
    struct  openvz_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr openvzDomainLookupByName(virConnectPtr conn,
                                             const char *name)
{
    struct openvz_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, name);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int openvzDomainGetInfo(virDomainPtr dom,
                               virDomainInfoPtr info)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int state;
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &state, NULL) == -1)
        goto cleanup;
    info->state = state;

    if (info->state != VIR_DOMAIN_RUNNING) {
        info->cpuTime = 0;
    } else {
        if (openvzGetProcessInfo(&(info->cpuTime), dom->id) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot read cputime for domain %d"), dom->id);
            goto cleanup;
        }
    }

    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
openvzDomainGetState(virDomainPtr dom,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = openvzGetVEStatus(vm, state, reason);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int openvzDomainIsActive(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    openvzDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

 cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}


static int openvzDomainIsPersistent(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    openvzDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

 cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int openvzDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    return 0;
}

static char *openvzDomainGetXMLDesc(virDomainPtr dom, unsigned int flags) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(vm->def, driver->caps,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


/*
 * Convenient helper to target a command line argv
 * and fill in an empty slot with the supplied
 * key value. This lets us declare the argv on the
 * stack and just splice in the domain name after
 */
#define PROGRAM_SENTINEL ((char *)0x1)
static void openvzSetProgramSentinal(const char **prog, const char *key)
{
    const char **tmp = prog;
    while (tmp && *tmp) {
        if (*tmp == PROGRAM_SENTINEL) {
            *tmp = key;
            break;
        }
        tmp++;
    }
}

static int openvzDomainSuspend(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "chkpnt", PROGRAM_SENTINEL, "--suspend", NULL};
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        openvzSetProgramSentinal(prog, vm->def->name);
        if (virRun(prog, NULL) < 0)
            goto cleanup;
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    }

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int openvzDomainResume(virDomainPtr dom)
{
  struct openvz_driver *driver = dom->conn->privateData;
  virDomainObjPtr vm;
  const char *prog[] = {VZCTL, "--quiet", "chkpnt", PROGRAM_SENTINEL, "--resume", NULL};
  int ret = -1;

  openvzDriverLock(driver);
  vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
  openvzDriverUnlock(driver);

  if (!vm) {
      virReportError(VIR_ERR_NO_DOMAIN, "%s",
                     _("no domain with matching uuid"));
      goto cleanup;
  }

  if (!virDomainObjIsActive(vm)) {
      virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Domain is not running"));
      goto cleanup;
  }

  if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
      openvzSetProgramSentinal(prog, vm->def->name);
      if (virRun(prog, NULL) < 0)
          goto cleanup;
      virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);
  }

  ret = 0;

 cleanup:
  if (vm)
      virObjectUnlock(vm);
  return ret;
}

static int
openvzDomainShutdownFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "stop", PROGRAM_SENTINEL, NULL};
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(prog, NULL) < 0)
        goto cleanup;

    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
    dom->id = -1;
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
openvzDomainShutdown(virDomainPtr dom)
{
    return openvzDomainShutdownFlags(dom, 0);
}

static int
openvzDomainDestroy(virDomainPtr dom)
{
    return openvzDomainShutdownFlags(dom, 0);
}

static int
openvzDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    return openvzDomainShutdownFlags(dom, flags);
}

static int openvzDomainReboot(virDomainPtr dom,
                              unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "restart", PROGRAM_SENTINEL, NULL};
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(prog, NULL) < 0)
        goto cleanup;
    ret = 0;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *
openvzGenerateVethName(int veid, char *dev_name_ve)
{
    int     ifNo = 0;
    char    *ret;

    if (sscanf(dev_name_ve, "%*[^0-9]%d", &ifNo) != 1)
        return NULL;
    ignore_value(virAsprintf(&ret, "veth%d.%d.", veid, ifNo));
    return ret;
}

static char *
openvzGenerateContainerVethName(int veid)
{
    char *temp = NULL;
    char *name = NULL;

    /* try to get line "^NETIF=..." from config */
    if (openvzReadVPSConfigParam(veid, "NETIF", &temp) <= 0) {
        ignore_value(VIR_STRDUP(name, "eth0"));
    } else {
        char *saveptr = NULL;
        char *s;
        int max = 0;

        /* get maximum interface number (actually, it is the last one) */
        for (s = strtok_r(temp, ";", &saveptr); s; s = strtok_r(NULL, ";", &saveptr)) {
            int x;

            if (sscanf(s, "ifname=eth%d", &x) != 1) return NULL;
            if (x > max) max = x;
        }

        /* set new name */
        ignore_value(virAsprintf(&name, "eth%d", max + 1));
    }

    VIR_FREE(temp);

    return name;
}

static int
openvzDomainSetNetwork(virConnectPtr conn, const char *vpsid,
                       virDomainNetDefPtr net,
                       virBufferPtr configBuf)
{
    int rc = -1;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    virMacAddr host_mac;
    char host_macaddr[VIR_MAC_STRING_BUFLEN];
    struct openvz_driver *driver =  conn->privateData;
    virCommandPtr cmd = NULL;
    char *guest_ifname = NULL;

    if (net == NULL)
       return 0;
    if (vpsid == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Container ID is not specified"));
        return -1;
    }

    if (net->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        net->type != VIR_DOMAIN_NET_TYPE_ETHERNET)
        return 0;

    cmd = virCommandNewArgList(VZCTL, "--quiet", "set", vpsid, NULL);

    virMacAddrFormat(&net->mac, macaddr);
    virDomainNetGenerateMAC(driver->xmlopt, &host_mac);
    virMacAddrFormat(&host_mac, host_macaddr);

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
         net->guestIP.nips == 0)) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        int veid = openvzGetVEID(vpsid);

        /* if net is ethernet and the user has specified guest interface name,
         * let's use it; otherwise generate a new one */
        if (net->ifname_guest) {
            if (VIR_STRDUP(guest_ifname, net->ifname_guest) < 0)
                goto cleanup;
        } else {
            guest_ifname = openvzGenerateContainerVethName(veid);
            if (guest_ifname == NULL) {
               virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                              _("Could not generate eth name for container"));
               goto cleanup;
            }
        }

        /* if user doesn't specified host interface name,
         * than we need to generate it */
        if (net->ifname == NULL) {
            net->ifname = openvzGenerateVethName(veid, guest_ifname);
            if (net->ifname == NULL) {
               virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                              _("Could not generate veth name"));
               goto cleanup;
            }
        }

        virBufferAdd(&buf, guest_ifname, -1); /* Guest dev */
        virBufferAsprintf(&buf, ",%s", macaddr); /* Guest dev mac */
        virBufferAsprintf(&buf, ",%s", net->ifname); /* Host dev */
        virBufferAsprintf(&buf, ",%s", host_macaddr); /* Host dev mac */

        if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (driver->version >= VZCTL_BRIDGE_MIN_VERSION) {
                virBufferAsprintf(&buf, ",%s", net->data.bridge.brname); /* Host bridge */
            } else {
                virBufferAsprintf(configBuf, "ifname=%s", guest_ifname);
                virBufferAsprintf(configBuf, ",mac=%s", macaddr); /* Guest dev mac */
                virBufferAsprintf(configBuf, ",host_ifname=%s", net->ifname); /* Host dev */
                virBufferAsprintf(configBuf, ",host_mac=%s", host_macaddr); /* Host dev mac */
                virBufferAsprintf(configBuf, ",bridge=%s", net->data.bridge.brname); /* Host bridge */
            }
        }

        /* --netif_add ifname[,mac,host_ifname,host_mac] */
        virCommandAddArg(cmd, "--netif_add");
        virCommandAddArgBuffer(cmd, &buf);
    } else if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
              net->guestIP.nips > 0) {
        size_t i;

        /* --ipadd ip */
        for (i = 0; i < net->guestIP.nips; i++) {
            char *ipStr = virSocketAddrFormat(&net->guestIP.ips[i]->address);
            if (!ipStr)
                goto cleanup;
            virCommandAddArgList(cmd, "--ipadd", ipStr, NULL);
            VIR_FREE(ipStr);
        }
    }

    /* TODO: processing NAT and physical device */

    virCommandAddArg(cmd, "--save");
    rc = virCommandRun(cmd, NULL);

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(guest_ifname);
    return rc;
}


static int
openvzDomainSetNetworkConfig(virConnectPtr conn,
                             virDomainDefPtr def)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *param;
    int first = 1;
    struct openvz_driver *driver =  conn->privateData;

    for (i = 0; i < def->nnets; i++) {
        if (driver->version < VZCTL_BRIDGE_MIN_VERSION &&
            def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (first)
                first = 0;
            else
                virBufferAddLit(&buf, ";");
        }

        if (openvzDomainSetNetwork(conn, def->name, def->nets[i], &buf) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not configure network"));
            goto exit;
        }
    }

    if (driver->version < VZCTL_BRIDGE_MIN_VERSION && def->nnets) {
        param = virBufferContentAndReset(&buf);
        if (param) {
            if (openvzWriteVPSConfigParam(strtoI(def->name), "NETIF", param) < 0) {
                VIR_FREE(param);
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot replace NETIF config"));
                return -1;
            }
            VIR_FREE(param);
        }
    }

    return 0;

 exit:
    virBufferFreeAndReset(&buf);
    return -1;
}


static virDomainPtr
openvzDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    struct openvz_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    openvzDriverLock(driver);
    if ((vmdef = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", vmdef->name, "\n") < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, vmdef,
                                   driver->xmlopt,
                                   0, NULL)))
        goto cleanup;
    vmdef = NULL;
    vm->persistent = 1;

    if (openvzSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (vm->def->nfss == 1) {
        if (openvzSetDiskQuota(vm->def, vm->def->fss[0], true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set disk quota"));
            goto cleanup;
        }
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    if (virDomainDefHasVcpusOffline(vm->def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("current vcpu count must equal maximum"));
        goto cleanup;
    }
    if (virDomainDefGetVcpusMax(vm->def)) {
        if (openvzDomainSetVcpusInternal(vm, virDomainDefGetVcpusMax(vm->def),
                                         driver->xmlopt) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set number of vCPUs"));
             goto cleanup;
        }
    }

    if (vm->def->mem.cur_balloon > 0) {
        if (openvzDomainSetMemoryInternal(vm, vm->def->mem.cur_balloon) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set memory size"));
             goto cleanup;
        }
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, -1);

 cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virObjectUnlock(vm);
    openvzDriverUnlock(driver);
    return dom;
}

static virDomainPtr
openvzDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return openvzDomainDefineXMLFlags(conn, xml, 0);
}

static virDomainPtr
openvzDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    struct openvz_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    const char *progstart[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINEL, NULL};
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    openvzDriverLock(driver);
    if ((vmdef = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains,
                                   vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    vmdef = NULL;
    /* All OpenVZ domains seem to be persistent - this is a bit of a violation
     * of this libvirt API which is intended for transient domain creation */
    vm->persistent = 1;

    if (openvzSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (vm->def->nfss == 1) {
        if (openvzSetDiskQuota(vm->def, vm->def->fss[0], true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set disk quota"));
            goto cleanup;
        }
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    openvzSetProgramSentinal(progstart, vm->def->name);

    if (virRun(progstart, NULL) < 0)
        goto cleanup;

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

    if (virDomainDefGetVcpusMax(vm->def) > 0) {
        if (openvzDomainSetVcpusInternal(vm, virDomainDefGetVcpusMax(vm->def),
                                         driver->xmlopt) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set number of vCPUs"));
            goto cleanup;
        }
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virObjectUnlock(vm);
    openvzDriverUnlock(driver);
    return dom;
}

static int
openvzDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINEL, NULL };
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, dom->name);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching id"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("domain is not in shutoff state"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0)
        goto cleanup;

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    dom->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainCreate(virDomainPtr dom)
{
    return openvzDomainCreateWithFlags(dom, 0);
}

static int
openvzDomainUndefineFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = { VZCTL, "--quiet", "destroy", PROGRAM_SENTINEL, NULL };
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    openvzDriverUnlock(driver);
    return ret;
}

static int
openvzDomainUndefine(virDomainPtr dom)
{
    return openvzDomainUndefineFlags(dom, 0);
}
static int
openvzDomainSetAutostart(virDomainPtr dom, int autostart)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINEL,
                           "--onboot", autostart ? "yes" : "no",
                           "--save", NULL };
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
openvzDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *value = NULL;
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzReadVPSConfigParam(strtoI(vm->def->name), "ONBOOT", &value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not read container config"));
        goto cleanup;
    }

    *autostart = 0;
    if (STREQ(value, "yes"))
        *autostart = 1;
    ret = 0;

 cleanup:
    VIR_FREE(value);

    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int openvzConnectGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    const char *type)
{
    if (type == NULL || STRCASEEQ(type, "openvz"))
        return 1028; /* OpenVZ has no limitation */

    virReportError(VIR_ERR_INVALID_ARG,
                   _("unknown type '%s'"), type);
    return -1;
}

static int
openvzDomainGetVcpusFlags(virDomainPtr dom ATTRIBUTE_UNUSED,
                          unsigned int flags)
{
    if (flags != (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported flags (0x%x)"), flags);
        return -1;
    }

    return openvzConnectGetMaxVcpus(NULL, "openvz");
}

static int openvzDomainGetMaxVcpus(virDomainPtr dom)
{
    return openvzDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                           VIR_DOMAIN_VCPU_MAXIMUM));
}

static int openvzDomainSetVcpusInternal(virDomainObjPtr vm,
                                        unsigned int nvcpus,
                                        virDomainXMLOptionPtr xmlopt)
{
    char        str_vcpus[32];
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINEL,
                           "--cpus", str_vcpus, "--save", NULL };
    unsigned int pcpus;
    pcpus = virHostCPUGetCount();
    if (pcpus > 0 && pcpus < nvcpus)
        nvcpus = pcpus;

    snprintf(str_vcpus, 31, "%d", nvcpus);
    str_vcpus[31] = '\0';

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0)
        return -1;

    if (virDomainDefSetVcpusMax(vm->def, nvcpus, xmlopt) < 0)
        return -1;

    if (virDomainDefSetVcpus(vm->def, nvcpus) < 0)
        return -1;

    return 0;
}

static int openvzDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                                     unsigned int flags)
{
    virDomainObjPtr         vm;
    struct openvz_driver   *driver = dom->conn->privateData;
    int                     ret = -1;

    if (flags != VIR_DOMAIN_AFFECT_LIVE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported flags (0x%x)"), flags);
        return -1;
    }

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (nvcpus <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Number of vCPUs should be >= 1"));
        goto cleanup;
    }

    if (openvzDomainSetVcpusInternal(vm, nvcpus, driver->xmlopt) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set number of vCPUs"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
openvzDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return openvzDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}

static virDrvOpenStatus openvzConnectOpen(virConnectPtr conn,
                                          virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                          virConfPtr conf ATTRIBUTE_UNUSED,
                                          unsigned int flags)
{
    struct openvz_driver *driver;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL) {
        if (!virFileExists("/proc/vz"))
            return VIR_DRV_OPEN_DECLINED;

        if (access("/proc/vz", W_OK) < 0)
            return VIR_DRV_OPEN_DECLINED;

        if (!(conn->uri = virURIParse("openvz:///system")))
            return VIR_DRV_OPEN_ERROR;
    } else {
        /* If scheme isn't 'openvz', then its for another driver */
        if (conn->uri->scheme == NULL ||
            STRNEQ(conn->uri->scheme, "openvz"))
            return VIR_DRV_OPEN_DECLINED;

        /* If server name is given, its for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* If path isn't /system, then they typoed, so tell them correct path */
        if (conn->uri->path == NULL ||
            STRNEQ(conn->uri->path, "/system")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected OpenVZ URI path '%s', try openvz:///system"),
                           conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }

        if (!virFileExists("/proc/vz")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("OpenVZ control file /proc/vz does not exist"));
            return VIR_DRV_OPEN_ERROR;
        }

        if (access("/proc/vz", W_OK) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("OpenVZ control file /proc/vz is not accessible"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    if (VIR_ALLOC(driver) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (!(driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(driver->caps = openvzCapsInit()))
        goto cleanup;

    if (!(driver->xmlopt = virDomainXMLOptionNew(&openvzDomainDefParserConfig,
                                                 NULL, NULL)))
        goto cleanup;

    if (openvzLoadDomains(driver) < 0)
        goto cleanup;

    if (openvzExtractVersion(driver) < 0)
        goto cleanup;

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    openvzFreeDriver(driver);
    return VIR_DRV_OPEN_ERROR;
};

static int openvzConnectClose(virConnectPtr conn)
{
    struct openvz_driver *driver = conn->privateData;

    openvzFreeDriver(driver);
    conn->privateData = NULL;

    return 0;
}

static const char *openvzConnectGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "OpenVZ";
}

static int openvzConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Encryption is not relevant / applicable to way we talk to openvz */
    return 0;
}

static int openvzConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* We run CLI tools directly so this is secure */
    return 1;
}

static int
openvzConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static char *openvzConnectGetCapabilities(virConnectPtr conn) {
    struct openvz_driver *driver = conn->privateData;
    char *ret;

    openvzDriverLock(driver);
    ret = virCapabilitiesFormatXML(driver->caps);
    openvzDriverUnlock(driver);

    return ret;
}

static int openvzConnectListDomains(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    int *ids, int nids)
{
    int got = 0;
    int veid;
    int outfd = -1;
    int rc = -1;
    int ret;
    char buf[32];
    char *endptr;
    virCommandPtr cmd = virCommandNewArgList(VZLIST, "-ovpsid", "-H", NULL);

    virCommandSetOutputFD(cmd, &outfd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        goto cleanup;

    while (got < nids) {
        ret = openvz_readline(outfd, buf, 32);
        if (!ret)
            break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse VPS ID %s"), buf);
            continue;
        }
        ids[got] = veid;
        got ++;
    }

    if (virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    if (VIR_CLOSE(outfd) < 0) {
        virReportSystemError(errno, "%s", _("failed to close file"));
        goto cleanup;
    }

    rc = got;
 cleanup:
    VIR_FORCE_CLOSE(outfd);
    virCommandFree(cmd);
    return rc;
}

static int openvzConnectNumOfDomains(virConnectPtr conn)
{
    struct openvz_driver *driver = conn->privateData;
    int n;

    openvzDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, true, NULL, NULL);
    openvzDriverUnlock(driver);

    return n;
}

static int openvzConnectListDefinedDomains(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           char **const names, int nnames) {
    int got = 0;
    int veid, outfd = -1, ret;
    int rc = -1;
    char vpsname[32];
    char buf[32];
    char *endptr;
    virCommandPtr cmd = virCommandNewArgList(VZLIST,
                                             "-ovpsid", "-H", "-S", NULL);

    /* the -S options lists only stopped domains */
    virCommandSetOutputFD(cmd, &outfd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        goto out;

    while (got < nnames) {
        ret = openvz_readline(outfd, buf, 32);
        if (!ret)
            break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse VPS ID %s"), buf);
            continue;
        }
        snprintf(vpsname, sizeof(vpsname), "%d", veid);
        if (VIR_STRDUP(names[got], vpsname) < 0)
            goto out;
        got ++;
    }

    if (virCommandWait(cmd, NULL) < 0)
        goto out;

    if (VIR_CLOSE(outfd) < 0) {
        virReportSystemError(errno, "%s", _("failed to close file"));
        goto out;
    }

    rc = got;
 out:
    VIR_FORCE_CLOSE(outfd);
    virCommandFree(cmd);
    if (rc < 0) {
        for (; got >= 0; got--)
            VIR_FREE(names[got]);
    }
    return rc;
}

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid)
{
    FILE *fp;
    char *line = NULL;
    size_t line_size = 0;
    unsigned long long usertime, systime, nicetime;
    int readvps = vpsid + 1;  /* ensure readvps is initially different */
    ssize_t ret;
    int err = 0;

/* read statistic from /proc/vz/vestat.
 sample:
Version: 2.2
   VEID     user      nice     system     uptime                 idle   other..
     33       78         0       1330   59454597      142650441835148   other..
     55      178         0       5340   59424597      542650441835148   other..
*/

    if ((fp = fopen("/proc/vz/vestat", "r")) == NULL)
        return -1;

    /*search line with VEID=vpsid*/
    while (1) {
        ret = getline(&line, &line_size, fp);
        if (ret < 0) {
            err = !feof(fp);
            break;
        }

        if (sscanf(line, "%d %llu %llu %llu",
                   &readvps, &usertime, &nicetime, &systime) == 4
            && readvps == vpsid) { /*found vpsid*/
            /* convert jiffies to nanoseconds */
            *cpuTime = (1000ull * 1000ull * 1000ull
                        * (usertime + nicetime  + systime)
                        / (unsigned long long)sysconf(_SC_CLK_TCK));
            break;
        }
    }

    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
    if (err)
        return -1;

    if (readvps != vpsid) /*not found*/
        return -1;

    return 0;
}

static int openvzConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct openvz_driver *driver =  conn->privateData;
    int n;

    openvzDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, false, NULL, NULL);
    openvzDriverUnlock(driver);

    return n;
}

static int
openvzDomainSetMemoryInternal(virDomainObjPtr vm,
                              unsigned long long mem)
{
    char str_mem[16];
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINEL,
        "--kmemsize", str_mem, "--save", NULL
    };

    /* memory has to be changed its format from kbyte to byte */
    snprintf(str_mem, sizeof(str_mem), "%llu", mem * 1024);

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0)
        goto cleanup;

    return 0;

 cleanup:
    return -1;
}


static int
openvzDomainGetBarrierLimit(virDomainPtr domain,
                            const char *param,
                            unsigned long long *barrier,
                            unsigned long long *limit)
{
    int ret = -1;
    char *endp, *output = NULL;
    const char *tmp;
    virCommandPtr cmd = virCommandNewArgList(VZLIST, "--no-header", NULL);

    virCommandSetOutputBuffer(cmd, &output);
    virCommandAddArgFormat(cmd, "-o%s.b,%s.l", param, param);
    virCommandAddArg(cmd, domain->name);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    tmp = output;
    virSkipSpaces(&tmp);
    if (virStrToLong_ull(tmp, &endp, 10, barrier) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Can't parse limit from "VZLIST" output '%s'"), output);
        goto cleanup;
    }
    tmp = endp;
    virSkipSpaces(&tmp);
    if (virStrToLong_ull(tmp, &endp, 10, limit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Can't parse barrier from "VZLIST" output '%s'"), output);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);
    return ret;
}


static int
openvzDomainSetBarrierLimit(virDomainPtr domain,
                            const  char *param,
                            unsigned long long barrier,
                            unsigned long long limit)
{
    int ret = -1;
    virCommandPtr cmd = virCommandNewArgList(VZCTL, "--quiet", "set", NULL);

    /* LONG_MAX indicates unlimited so reject larger values */
    if (barrier > LONG_MAX || limit > LONG_MAX) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to set %s for %s: value too large"), param,
                       domain->name);
        goto cleanup;
    }

    virCommandAddArg(cmd, domain->name);
    virCommandAddArgFormat(cmd, "--%s", param);
    virCommandAddArgFormat(cmd, "%llu:%llu", barrier, limit);
    virCommandAddArg(cmd, "--save");
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}


static int
openvzDomainGetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int *nparams,
                                unsigned int flags)
{
    size_t i;
    int result = -1;
    const char *name;
    long kb_per_pages;
    unsigned long long barrier, limit, val;

    virCheckFlags(0, -1);

    kb_per_pages = openvzKBPerPages();
    if (kb_per_pages < 0)
        goto cleanup;

    if (*nparams == 0) {
        *nparams = OPENVZ_NB_MEM_PARAM;
        return 0;
    }

    for (i = 0; i <= *nparams; i++) {
        virMemoryParameterPtr param = &params[i];

        switch (i) {
        case 0:
            name = "privvmpages";
            if (openvzDomainGetBarrierLimit(domain, name, &barrier, &limit) < 0)
                goto cleanup;

            val = (limit == LONG_MAX) ? VIR_DOMAIN_MEMORY_PARAM_UNLIMITED : limit * kb_per_pages;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        case 1:
            name = "privvmpages";
            if (openvzDomainGetBarrierLimit(domain, name, &barrier, &limit) < 0)
                goto cleanup;

            val = (barrier == LONG_MAX) ? VIR_DOMAIN_MEMORY_PARAM_UNLIMITED : barrier * kb_per_pages;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        case 2:
            name = "vmguarpages";
            if (openvzDomainGetBarrierLimit(domain, name, &barrier, &limit) < 0)
                goto cleanup;

            val = (barrier == LONG_MAX) ? 0ull : barrier * kb_per_pages;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        }
    }

    if (*nparams > OPENVZ_NB_MEM_PARAM)
        *nparams = OPENVZ_NB_MEM_PARAM;
    result = 0;

 cleanup:
    return result;
}


static int
openvzDomainSetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    size_t i;
    int result = -1;
    long kb_per_pages;

    kb_per_pages = openvzKBPerPages();
    if (kb_per_pages < 0)
        goto cleanup;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_MEMORY_HARD_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                               VIR_TYPED_PARAM_ULLONG,
                               NULL) < 0)
        return -1;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];
        unsigned long long barrier, limit;

        if (STREQ(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT)) {
            if (openvzDomainGetBarrierLimit(domain, "privvmpages",
                                            &barrier, &limit) < 0)
                goto cleanup;
            limit = params[i].value.ul / kb_per_pages;
            if (openvzDomainSetBarrierLimit(domain, "privvmpages",
                                            barrier, limit) < 0)
                goto cleanup;
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT)) {
            if (openvzDomainGetBarrierLimit(domain, "privvmpages",
                                            &barrier, &limit) < 0)
                goto cleanup;
            barrier = params[i].value.ul / kb_per_pages;
            if (openvzDomainSetBarrierLimit(domain, "privvmpages",
                                            barrier, limit) < 0)
                goto cleanup;
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_MIN_GUARANTEE)) {
            barrier = params[i].value.ul / kb_per_pages;
            if (openvzDomainSetBarrierLimit(domain, "vmguarpages",
                                            barrier, LONG_MAX) < 0)
                goto cleanup;
        }
    }
    result = 0;
 cleanup:
    return result;
}


static int
openvzGetVEStatus(virDomainObjPtr vm, int *status, int *reason)
{
    virCommandPtr cmd;
    char *outbuf;
    char *line;
    int state;
    int ret = -1;

    cmd = virCommandNewArgList(VZLIST, vm->def->name, "-ostatus", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if ((line = strchr(outbuf, '\n')) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to parse vzlist output"));
        goto cleanup;
    }
    *line++ = '\0';

    state = virDomainObjGetState(vm, reason);

    if (STREQ(outbuf, "running")) {
        /* There is no way to detect whether a domain is paused or not
         * with vzlist */
        if (state == VIR_DOMAIN_PAUSED)
            *status = state;
        else
            *status = VIR_DOMAIN_RUNNING;
    } else {
        *status = VIR_DOMAIN_SHUTOFF;
    }

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    return ret;
}

static int
openvzDomainInterfaceStats(virDomainPtr dom,
                           const char *path,
                           virDomainInterfaceStatsPtr stats)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    size_t i;
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
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
                       _("invalid path, '%s' is not a known interface"), path);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
openvzUpdateDevice(virDomainDefPtr vmdef,
                   virDomainDeviceDefPtr dev,
                   bool persist)
{
    virDomainFSDefPtr fs, cur;
    int pos;

    if (dev->type == VIR_DOMAIN_DEVICE_FS) {
        fs = dev->data.fs;
        pos = virDomainFSIndexByName(vmdef, fs->dst);

        if (pos < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("target %s doesn't exist."), fs->dst);
            return -1;
        }
        cur = vmdef->fss[pos];

        /* We only allow updating the quota */
        if (STRNEQ(cur->src->path, fs->src->path)
            || cur->type != fs->type
            || cur->accessmode != fs->accessmode
            || cur->wrpolicy != fs->wrpolicy
            || cur->readonly != fs->readonly) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can only modify disk quota"));
            return -1;
        }

        if (openvzSetDiskQuota(vmdef, fs, persist) < 0)
            return -1;
        cur->space_hard_limit = fs->space_hard_limit;
        cur->space_soft_limit = fs->space_soft_limit;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Can't modify device type '%s'"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    return 0;
}


static int
openvzDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    int ret = -1;
    int veid;
    struct  openvz_driver *driver = dom->conn->privateData;
    virDomainDeviceDefPtr dev = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    bool persist = false;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virStrToLong_i(vm->def->name, NULL, 10, &veid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not convert domain name to VEID"));
        goto cleanup;
    }

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    dev = virDomainDeviceDefParse(xml, def, driver->caps, driver->xmlopt,
                                  VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (!dev)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        persist = true;

    if (openvzUpdateDevice(def, dev, persist) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    openvzDriverUnlock(driver);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
openvzConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    struct openvz_driver *driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    openvzDriverLock(driver);
    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 NULL, flags);
    openvzDriverUnlock(driver);

    return ret;
}



static int
openvzNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                  virNodeInfoPtr nodeinfo)
{
    return virCapabilitiesGetNodeInfo(nodeinfo);
}


static int
openvzNodeGetCPUStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                      int cpuNum,
                      virNodeCPUStatsPtr params,
                      int *nparams,
                      unsigned int flags)
{
    return virHostCPUGetStats(cpuNum, params, nparams, flags);
}


static int
openvzNodeGetMemoryStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                         int cellNum,
                         virNodeMemoryStatsPtr params,
                         int *nparams,
                         unsigned int flags)
{
    return virHostMemGetStats(cellNum, params, nparams, flags);
}


static int
openvzNodeGetCellsFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED,
                             unsigned long long *freeMems,
                             int startCell,
                             int maxCells)
{
    return virHostMemGetCellsFree(freeMems, startCell, maxCells);
}


static unsigned long long
openvzNodeGetFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    unsigned long long freeMem;
    if (virHostMemGetInfo(NULL, &freeMem) < 0)
        return 0;
    return freeMem;
}


static int
openvzNodeGetCPUMap(virConnectPtr conn ATTRIBUTE_UNUSED,
                    unsigned char **cpumap,
                    unsigned int *online,
                    unsigned int flags)
{
    return virHostCPUGetMap(cpumap, online, flags);
}


static int
openvzConnectSupportsFeature(virConnectPtr conn ATTRIBUTE_UNUSED, int feature)
{
    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_PARAMS:
    case VIR_DRV_FEATURE_MIGRATION_V3:
        return 1;
    default:
        return 0;
    }
}


static char *
openvzDomainMigrateBegin3Params(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                char **cookieout ATTRIBUTE_UNUSED,
                                int *cookieoutlen ATTRIBUTE_UNUSED,
                                unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    struct openvz_driver *driver = domain->conn->privateData;
    char *xml = NULL;
    int status;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        return NULL;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    xml = virDomainDefFormat(vm->def, driver->caps,
                             VIR_DOMAIN_DEF_FORMAT_SECURE);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return xml;
}

static int
openvzDomainMigratePrepare3Params(virConnectPtr dconn,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein ATTRIBUTE_UNUSED,
                                  int cookieinlen ATTRIBUTE_UNUSED,
                                  char **cookieout ATTRIBUTE_UNUSED,
                                  int *cookieoutlen ATTRIBUTE_UNUSED,
                                  char **uri_out,
                                  unsigned int fflags ATTRIBUTE_UNUSED)
{
    struct openvz_driver *driver = dconn->privateData;
    const char *dom_xml = NULL;
    const char *uri_in = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    char *my_hostname = NULL;
    const char *hostname = NULL;
    virURIPtr uri = NULL;
    int ret = -1;

    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto error;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri_in) < 0)
        goto error;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        goto error;
    }

    if (!(def = virDomainDefParseString(dom_xml, driver->caps, driver->xmlopt,
                                        NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto error;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto error;
    def = NULL;

    if (!uri_in) {
        if ((my_hostname = virGetHostname()) == NULL)
            goto error;

        if (STRPREFIX(my_hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost,"
                             " but migration requires an FQDN"));
            goto error;
        }
    } else {
        uri = virURIParse(uri_in);

        if (uri == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unable to parse URI: %s"),
                           uri_in);
            goto error;
        }

        if (uri->server == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing host in migration URI: %s"),
                           uri_in);
            goto error;
        } else {
            hostname = uri->server;
        }
    }

    if (virAsprintf(uri_out, "ssh://%s", hostname) < 0)
        goto error;

    ret = 0;
    goto done;

 error:
    virDomainDefFree(def);
    if (vm) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

 done:
    VIR_FREE(my_hostname);
    virURIFree(uri);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
openvzDomainMigratePerform3Params(virDomainPtr domain,
                                  const char *dconnuri ATTRIBUTE_UNUSED,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein ATTRIBUTE_UNUSED,
                                  int cookieinlen ATTRIBUTE_UNUSED,
                                  char **cookieout ATTRIBUTE_UNUSED,
                                  int *cookieoutlen ATTRIBUTE_UNUSED,
                                  unsigned int flags)
{
    struct openvz_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    const char *uri_str = NULL;
    virURIPtr uri = NULL;
    virCommandPtr cmd = NULL;
    int ret = -1;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri_str) < 0)
        goto cleanup;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    /* parse dst host:port from uri */
    uri = virURIParse(uri_str);
    if (uri == NULL || uri->server == NULL)
        goto cleanup;

    cmd = virCommandNew(VZMIGRATE);
    if (flags & VIR_MIGRATE_LIVE)
        virCommandAddArg(cmd, "--live");
    virCommandAddArg(cmd, uri->server);
    virCommandAddArg(cmd, vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    virURIFree(uri);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static virDomainPtr
openvzDomainMigrateFinish3Params(virConnectPtr dconn,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 const char *cookiein ATTRIBUTE_UNUSED,
                                 int cookieinlen ATTRIBUTE_UNUSED,
                                 char **cookieout ATTRIBUTE_UNUSED,
                                 int *cookieoutlen ATTRIBUTE_UNUSED,
                                 unsigned int flags,
                                 int cancelled)
{
    struct openvz_driver *driver = dconn->privateData;
    virDomainObjPtr vm = NULL;
    const char *dname = NULL;
    virDomainPtr dom = NULL;
    int status;

    if (cancelled)
        goto cleanup;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0)
        goto cleanup;

    if (!dname ||
        !(vm = virDomainObjListFindByName(driver->domains, dname))) {
        /* Migration obviously failed if the domain doesn't exist */
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Migration failed. No domain on destination host "
                         "with matching name '%s'"),
                       NULLSTR(dname));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not running on destination host"));
        goto cleanup;
    }

    vm->def->id = strtoI(vm->def->name);
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_MIGRATED);

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
openvzDomainMigrateConfirm3Params(virDomainPtr domain,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein ATTRIBUTE_UNUSED,
                                  int cookieinlen ATTRIBUTE_UNUSED,
                                  unsigned int flags,
                                  int cancelled)
{
    struct openvz_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int status;
    int ret = -1;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    openvzDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (cancelled) {
        if (openvzGetVEStatus(vm, &status, NULL) == -1)
            goto cleanup;

        if (status == VIR_DOMAIN_RUNNING) {
            ret = 0;
        } else {
            VIR_DEBUG("Domain '%s' does not recover after failed migration",
                      vm->def->name);
        }

        goto cleanup;
    }

    vm->def->id = -1;

    VIR_DEBUG("Domain '%s' successfully migrated", vm->def->name);

    virDomainObjListRemove(driver->domains, vm);
    vm = NULL;

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
openvzDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openvzDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = 0;

 cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}



static virHypervisorDriver openvzHypervisorDriver = {
    .name = "OPENVZ",
    .connectOpen = openvzConnectOpen, /* 0.3.1 */
    .connectClose = openvzConnectClose, /* 0.3.1 */
    .connectGetType = openvzConnectGetType, /* 0.3.1 */
    .connectGetVersion = openvzConnectGetVersion, /* 0.5.0 */
    .connectGetHostname = openvzConnectGetHostname, /* 0.9.12 */
    .connectGetMaxVcpus = openvzConnectGetMaxVcpus, /* 0.4.6 */
    .nodeGetInfo = openvzNodeGetInfo, /* 0.3.2 */
    .nodeGetCPUStats = openvzNodeGetCPUStats, /* 0.9.12 */
    .nodeGetMemoryStats = openvzNodeGetMemoryStats, /* 0.9.12 */
    .nodeGetCellsFreeMemory = openvzNodeGetCellsFreeMemory, /* 0.9.12 */
    .nodeGetFreeMemory = openvzNodeGetFreeMemory, /* 0.9.12 */
    .nodeGetCPUMap = openvzNodeGetCPUMap, /* 1.0.0 */
    .connectGetCapabilities = openvzConnectGetCapabilities, /* 0.4.6 */
    .connectListDomains = openvzConnectListDomains, /* 0.3.1 */
    .connectNumOfDomains = openvzConnectNumOfDomains, /* 0.3.1 */
    .connectListAllDomains = openvzConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = openvzDomainCreateXML, /* 0.3.3 */
    .domainLookupByID = openvzDomainLookupByID, /* 0.3.1 */
    .domainLookupByUUID = openvzDomainLookupByUUID, /* 0.3.1 */
    .domainLookupByName = openvzDomainLookupByName, /* 0.3.1 */
    .domainSuspend = openvzDomainSuspend, /* 0.8.3 */
    .domainResume = openvzDomainResume, /* 0.8.3 */
    .domainShutdown = openvzDomainShutdown, /* 0.3.1 */
    .domainShutdownFlags = openvzDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = openvzDomainReboot, /* 0.3.1 */
    .domainDestroy = openvzDomainDestroy, /* 0.3.1 */
    .domainDestroyFlags = openvzDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = openvzDomainGetOSType, /* 0.3.1 */
    .domainGetMemoryParameters = openvzDomainGetMemoryParameters, /* 0.9.12 */
    .domainSetMemoryParameters = openvzDomainSetMemoryParameters, /* 0.9.12 */
    .domainGetInfo = openvzDomainGetInfo, /* 0.3.1 */
    .domainGetState = openvzDomainGetState, /* 0.9.2 */
    .domainSetVcpus = openvzDomainSetVcpus, /* 0.4.6 */
    .domainSetVcpusFlags = openvzDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = openvzDomainGetVcpusFlags, /* 0.8.5 */
    .domainGetMaxVcpus = openvzDomainGetMaxVcpus, /* 0.4.6 */
    .domainGetXMLDesc = openvzDomainGetXMLDesc, /* 0.4.6 */
    .connectListDefinedDomains = openvzConnectListDefinedDomains, /* 0.3.1 */
    .connectNumOfDefinedDomains = openvzConnectNumOfDefinedDomains, /* 0.3.1 */
    .domainCreate = openvzDomainCreate, /* 0.3.1 */
    .domainCreateWithFlags = openvzDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = openvzDomainDefineXML, /* 0.3.3 */
    .domainDefineXMLFlags = openvzDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = openvzDomainUndefine, /* 0.3.3 */
    .domainUndefineFlags = openvzDomainUndefineFlags, /* 0.9.4 */
    .domainGetAutostart = openvzDomainGetAutostart, /* 0.4.6 */
    .domainSetAutostart = openvzDomainSetAutostart, /* 0.4.6 */
    .domainInterfaceStats = openvzDomainInterfaceStats, /* 0.9.12 */
    .connectIsEncrypted = openvzConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = openvzConnectIsSecure, /* 0.7.3 */
    .domainIsActive = openvzDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = openvzDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = openvzDomainIsUpdated, /* 0.8.6 */
    .connectIsAlive = openvzConnectIsAlive, /* 0.9.8 */
    .domainUpdateDeviceFlags = openvzDomainUpdateDeviceFlags, /* 0.9.13 */
    .domainGetHostname = openvzDomainGetHostname, /* 0.10.0 */
    .connectSupportsFeature = openvzConnectSupportsFeature, /* 1.2.8 */
    .domainMigrateBegin3Params = openvzDomainMigrateBegin3Params, /* 1.2.8 */
    .domainMigratePrepare3Params = openvzDomainMigratePrepare3Params, /* 1.2.8 */
    .domainMigratePerform3Params = openvzDomainMigratePerform3Params, /* 1.2.8 */
    .domainMigrateFinish3Params = openvzDomainMigrateFinish3Params, /* 1.2.8 */
    .domainMigrateConfirm3Params = openvzDomainMigrateConfirm3Params, /* 1.2.8 */
    .domainHasManagedSaveImage = openvzDomainHasManagedSaveImage, /* 1.2.13 */
};

static virConnectDriver openvzConnectDriver = {
    .hypervisorDriver = &openvzHypervisorDriver,
};

int openvzRegister(void)
{
    return virRegisterConnectDriver(&openvzConnectDriver,
                                    false);
}
