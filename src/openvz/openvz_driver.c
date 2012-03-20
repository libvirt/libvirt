/*
 * openvz_driver.c: core driver methods for managing OpenVZ VEs
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
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
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "openvz_driver.h"
#include "buf.h"
#include "util.h"
#include "openvz_conf.h"
#include "nodeinfo.h"
#include "memory.h"
#include "virfile.h"
#include "logging.h"
#include "command.h"
#include "viruri.h"

#define VIR_FROM_THIS VIR_FROM_OPENVZ

#define OPENVZ_MAX_ARG 28
#define CMDBUF_LEN 1488
#define CMDOP_LEN 288

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid);
static int openvzGetMaxVCPUs(virConnectPtr conn, const char *type);
static int openvzDomainGetMaxVcpus(virDomainPtr dom);
static int openvzDomainSetVcpusInternal(virDomainObjPtr vm,
                                        unsigned int nvcpus);
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

static void cmdExecFree(const char *cmdExec[])
{
    int i=-1;
    while (cmdExec[++i]) {
        VIR_FREE(cmdExec[i]);
    }
}

/* generate arguments to create OpenVZ container
   return -1 - error
           0 - OK
*/
static int
openvzDomainDefineCmd(const char *args[],
                      int maxarg, virDomainDefPtr vmdef)
{
    int narg;

    for (narg = 0; narg < maxarg; narg++)
        args[narg] = NULL;

    if (vmdef == NULL) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Container is not defined"));
        return -1;
    }

#define ADD_ARG(thisarg)                                                \
    do {                                                                \
        if (narg >= maxarg)                                             \
                 goto no_memory;                                        \
        args[narg++] = thisarg;                                         \
    } while (0)

#define ADD_ARG_LIT(thisarg)                                            \
    do {                                                                \
        if (narg >= maxarg)                                             \
                 goto no_memory;                                        \
        if ((args[narg++] = strdup(thisarg)) == NULL)                   \
            goto no_memory;                                             \
    } while (0)

    narg = 0;
    ADD_ARG_LIT(VZCTL);
    ADD_ARG_LIT("--quiet");
    ADD_ARG_LIT("create");

    ADD_ARG_LIT(vmdef->name);
    ADD_ARG_LIT("--name");
    ADD_ARG_LIT(vmdef->name);

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_TEMPLATE) {
        ADD_ARG_LIT("--ostemplate");
        ADD_ARG_LIT(vmdef->fss[0]->src);
    }
#if 0
    if ((vmdef->profile && *(vmdef->profile))) {
        ADD_ARG_LIT("--config");
        ADD_ARG_LIT(vmdef->profile);
    }
#endif

    ADD_ARG(NULL);
    return 0;

no_memory:
    openvzError(VIR_ERR_INTERNAL_ERROR,
                _("Could not put argument to %s"), VZCTL);
    return -1;

#undef ADD_ARG
#undef ADD_ARG_LIT
}


static int openvzSetInitialConfig(virDomainDefPtr vmdef)
{
    int ret = -1;
    int vpsid;
    char * confdir = NULL;
    const char *prog[OPENVZ_MAX_ARG];
    prog[0] = NULL;

    if (vmdef->nfss > 1) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("only one filesystem supported"));
        goto cleanup;
    }

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_TEMPLATE &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
    {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("filesystem is not of type 'template' or 'mount'"));
        goto cleanup;
    }


    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_MOUNT)
    {

        if (virStrToLong_i(vmdef->name, NULL, 10, &vpsid) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not convert domain name to VEID"));
            goto cleanup;
        }

        if (openvzCopyDefaultConfig(vpsid) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not copy default config"));
            goto cleanup;
        }

        if (openvzWriteVPSConfigParam(vpsid, "VE_PRIVATE", vmdef->fss[0]->src) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not set the source dir for the filesystem"));
            goto cleanup;
        }
    }
    else
    {
        if (openvzDomainDefineCmd(prog, OPENVZ_MAX_ARG, vmdef) < 0) {
            VIR_ERROR(_("Error creating command for container"));
            goto cleanup;
        }

        if (virRun(prog, NULL) < 0) {
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
  VIR_FREE(confdir);
  cmdExecFree(prog);
  return ret;
}


static virDomainPtr openvzDomainLookupByID(virConnectPtr conn,
                                           int id) {
    struct openvz_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openvzDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, id);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, NULL);
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

static int openvzGetVersion(virConnectPtr conn, unsigned long *version) {
    struct  openvz_driver *driver = conn->privateData;
    openvzDriverLock(driver);
    *version = driver->version;
    openvzDriverUnlock(driver);
    return 0;
}

static char *openvzGetOSType(virDomainPtr dom)
{
    struct  openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (!(ret = strdup(vm->def->os.type)))
        virReportOOMError();

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid) {
    struct  openvz_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, NULL);
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

static virDomainPtr openvzDomainLookupByName(virConnectPtr conn,
                                             const char *name) {
    struct openvz_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openvzDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, name);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, NULL);
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

static int openvzDomainGetInfo(virDomainPtr dom,
                               virDomainInfoPtr info) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int state;
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
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
            openvzError(VIR_ERR_OPERATION_FAILED,
                        _("cannot read cputime for domain %d"), dom->id);
            goto cleanup;
        }
    }

    info->maxMem = vm->def->mem.max_balloon;
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
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
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = openvzGetVEStatus(vm, state, reason);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int openvzDomainIsActive(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    openvzDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);
    if (!obj) {
        openvzError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}


static int openvzDomainIsPersistent(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    openvzDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);
    if (!obj) {
        openvzError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
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
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(vm->def, flags);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


/*
 * Convenient helper to target a command line argv
 * and fill in an empty slot with the supplied
 * key value. This lets us declare the argv on the
 * stack and just splice in the domain name after
 */
#define PROGRAM_SENTINAL ((char *)0x1)
static void openvzSetProgramSentinal(const char **prog, const char *key)
{
    const char **tmp = prog;
    while (tmp && *tmp) {
        if (*tmp == PROGRAM_SENTINAL) {
            *tmp = key;
            break;
        }
        tmp++;
    }
}

static int openvzDomainSuspend(virDomainPtr dom) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "chkpnt", PROGRAM_SENTINAL, "--suspend", NULL};
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        openvzError(VIR_ERR_OPERATION_INVALID, "%s",
                    _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        openvzSetProgramSentinal(prog, vm->def->name);
        if (virRun(prog, NULL) < 0) {
            goto cleanup;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int openvzDomainResume(virDomainPtr dom) {
  struct openvz_driver *driver = dom->conn->privateData;
  virDomainObjPtr vm;
  const char *prog[] = {VZCTL, "--quiet", "chkpnt", PROGRAM_SENTINAL, "--resume", NULL};
  int ret = -1;

  openvzDriverLock(driver);
  vm = virDomainFindByUUID(&driver->domains, dom->uuid);
  openvzDriverUnlock(driver);

  if (!vm) {
      openvzError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching uuid"));
      goto cleanup;
  }

  if (!virDomainObjIsActive(vm)) {
      openvzError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not running"));
      goto cleanup;
  }

  if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
      openvzSetProgramSentinal(prog, vm->def->name);
      if (virRun(prog, NULL) < 0) {
          goto cleanup;
      }
      virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);
  }

  ret = 0;

cleanup:
  if (vm)
      virDomainObjUnlock(vm);
  return ret;
}

static int
openvzDomainShutdownFlags(virDomainPtr dom,
                          unsigned int flags) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "stop", PROGRAM_SENTINAL, NULL};
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
    if (status != VIR_DOMAIN_RUNNING) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        virDomainObjUnlock(vm);
    return ret;
}

static int
openvzDomainShutdown(virDomainPtr dom)
{
    return openvzDomainShutdownFlags(dom, 0);
}

static int openvzDomainReboot(virDomainPtr dom,
                              unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "restart", PROGRAM_SENTINAL, NULL};
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
    if (status != VIR_DOMAIN_RUNNING) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(prog, NULL) < 0)
        goto cleanup;
    ret = 0;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static char *
openvzGenerateVethName(int veid, char *dev_name_ve)
{
    char    dev_name[32];
    int     ifNo = 0;

    if (sscanf(dev_name_ve, "%*[^0-9]%d", &ifNo) != 1)
        return NULL;
    if (snprintf(dev_name, sizeof(dev_name), "veth%d.%d", veid, ifNo) < 7)
        return NULL;
    return strdup(dev_name);
}

static char *
openvzGenerateContainerVethName(int veid)
{
    char *temp = NULL;
    char *name = NULL;

    /* try to get line "^NETIF=..." from config */
    if (openvzReadVPSConfigParam(veid, "NETIF", &temp) <= 0) {
        name = strdup("eth0");
    } else {
        char *saveptr = NULL;
        char *s;
        int max = 0;

        /* get maximum interface number (actually, it is the last one) */
        for (s=strtok_r(temp, ";", &saveptr); s; s=strtok_r(NULL, ";", &saveptr)) {
            int x;

            if (sscanf(s, "ifname=eth%d", &x) != 1) return NULL;
            if (x > max) max = x;
        }

        /* set new name */
        ignore_value(virAsprintf(&name, "eth%d", max + 1));
    }

    VIR_FREE(temp);

    if (name == NULL) {
        virReportOOMError();
    }

    return name;
}

static int
openvzDomainSetNetwork(virConnectPtr conn, const char *vpsid,
                       virDomainNetDefPtr net,
                       virBufferPtr configBuf)
{
    int rc = 0, narg;
    const char *prog[OPENVZ_MAX_ARG];
    char macaddr[VIR_MAC_STRING_BUFLEN];
    unsigned char host_mac[VIR_MAC_BUFLEN];
    char host_macaddr[VIR_MAC_STRING_BUFLEN];
    struct openvz_driver *driver =  conn->privateData;
    char *opt = NULL;

#define ADD_ARG_LIT(thisarg)                                            \
    do {                                                                \
        if (narg >= OPENVZ_MAX_ARG)                                             \
                 goto no_memory;                                        \
        if ((prog[narg++] = strdup(thisarg)) == NULL)                   \
            goto no_memory;                                             \
    } while (0)


    if (net == NULL)
       return 0;
    if (vpsid == NULL) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Container ID is not specified"));
        return -1;
    }

    for (narg = 0; narg < OPENVZ_MAX_ARG; narg++)
        prog[narg] = NULL;

    narg = 0;

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        net->type == VIR_DOMAIN_NET_TYPE_ETHERNET) {
        ADD_ARG_LIT(VZCTL);
        ADD_ARG_LIT("--quiet");
        ADD_ARG_LIT("set");
        ADD_ARG_LIT(vpsid);
    }

    virMacAddrFormat(net->mac, macaddr);
    virCapabilitiesGenerateMac(driver->caps, host_mac);
    virMacAddrFormat(host_mac, host_macaddr);

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
         net->data.ethernet.ipaddr == NULL)) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        int veid = openvzGetVEID(vpsid);

        /* --netif_add ifname[,mac,host_ifname,host_mac] */
        ADD_ARG_LIT("--netif_add") ;

        /* if user doesn't specify guest interface name,
         * then we need to generate it */
        if (net->data.ethernet.dev == NULL) {
            net->data.ethernet.dev = openvzGenerateContainerVethName(veid);
            if (net->data.ethernet.dev == NULL) {
               openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not generate eth name for container"));
               rc = -1;
               goto exit;
            }
        }

        /* if user doesn't specified host interface name,
         * than we need to generate it */
        if (net->ifname == NULL) {
            net->ifname = openvzGenerateVethName(veid, net->data.ethernet.dev);
            if (net->ifname == NULL) {
               openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not generate veth name"));
               rc = -1;
               goto exit;
            }
        }

        virBufferAdd(&buf, net->data.ethernet.dev, -1); /* Guest dev */
        virBufferAsprintf(&buf, ",%s", macaddr); /* Guest dev mac */
        virBufferAsprintf(&buf, ",%s", net->ifname); /* Host dev */
        virBufferAsprintf(&buf, ",%s", host_macaddr); /* Host dev mac */

        if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (driver->version >= VZCTL_BRIDGE_MIN_VERSION) {
                virBufferAsprintf(&buf, ",%s", net->data.bridge.brname); /* Host bridge */
            } else {
                virBufferAsprintf(configBuf, "ifname=%s", net->data.ethernet.dev);
                virBufferAsprintf(configBuf, ",mac=%s", macaddr); /* Guest dev mac */
                virBufferAsprintf(configBuf, ",host_ifname=%s", net->ifname); /* Host dev */
                virBufferAsprintf(configBuf, ",host_mac=%s", host_macaddr); /* Host dev mac */
                virBufferAsprintf(configBuf, ",bridge=%s", net->data.bridge.brname); /* Host bridge */
            }
        }

        if (!(opt = virBufferContentAndReset(&buf)))
            goto no_memory;

        ADD_ARG_LIT(opt) ;
        VIR_FREE(opt);
    } else if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
              net->data.ethernet.ipaddr != NULL) {
        /* --ipadd ip */
        ADD_ARG_LIT("--ipadd") ;
        ADD_ARG_LIT(net->data.ethernet.ipaddr) ;
    }

    /* TODO: processing NAT and physical device */

    if (prog[0] != NULL) {
        ADD_ARG_LIT("--save");
        if (virRun(prog, NULL) < 0) {
           rc = -1;
           goto exit;
        }
    }

 exit:
    cmdExecFree(prog);
    return rc;

 no_memory:
    VIR_FREE(opt);
    openvzError(VIR_ERR_INTERNAL_ERROR,
                _("Could not put argument to %s"), VZCTL);
    cmdExecFree(prog);
    return -1;

#undef ADD_ARG_LIT
}


static int
openvzDomainSetNetworkConfig(virConnectPtr conn,
                             virDomainDefPtr def)
{
    unsigned int i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *param;
    int first = 1;
    struct openvz_driver *driver =  conn->privateData;

    for (i = 0 ; i < def->nnets ; i++) {
        if (driver->version < VZCTL_BRIDGE_MIN_VERSION &&
            def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (first)
                first = 0;
            else
                virBufferAddLit(&buf, ";");
        }

        if (openvzDomainSetNetwork(conn, def->name, def->nets[i], &buf) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not configure network"));
            goto exit;
        }
    }

    if (driver->version < VZCTL_BRIDGE_MIN_VERSION && def->nnets) {
        param = virBufferContentAndReset(&buf);
        if (param) {
            if (openvzWriteVPSConfigParam(strtoI(def->name), "NETIF", param) < 0) {
                VIR_FREE(param);
                openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
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
openvzDomainDefineXML(virConnectPtr conn, const char *xml)
{
    struct openvz_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;

    openvzDriverLock(driver);
    if ((vmdef = virDomainDefParseString(driver->caps, xml,
                                         1 << VIR_DOMAIN_VIRT_OPENVZ,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    vm = virDomainFindByName(&driver->domains, vmdef->name);
    if (vm) {
        openvzError(VIR_ERR_OPERATION_FAILED,
                    _("Already an OPENVZ VM active with the id '%s'"),
                    vmdef->name);
        goto cleanup;
    }
    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, vmdef, false)))
        goto cleanup;
    vmdef = NULL;
    vm->persistent = 1;

    if (openvzSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    /* TODO: set quota */

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    if (vm->def->vcpus != vm->def->maxvcpus) {
        openvzError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                    _("current vcpu count must equal maximum"));
        goto cleanup;
    }
    if (vm->def->maxvcpus > 0) {
        if (openvzDomainSetVcpusInternal(vm, vm->def->maxvcpus) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not set number of virtual cpu"));
             goto cleanup;
        }
    }

    if (vm->def->mem.cur_balloon > 0) {
        if (openvzDomainSetMemoryInternal(vm, vm->def->mem.cur_balloon) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not set memory size"));
             goto cleanup;
        }
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = -1;

cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virDomainObjUnlock(vm);
    openvzDriverUnlock(driver);
    return dom;
}

static virDomainPtr
openvzDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    struct openvz_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    const char *progstart[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINAL, NULL};

    virCheckFlags(0, NULL);

    openvzDriverLock(driver);
    if ((vmdef = virDomainDefParseString(driver->caps, xml,
                                         1 << VIR_DOMAIN_VIRT_OPENVZ,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    vm = virDomainFindByName(&driver->domains, vmdef->name);
    if (vm) {
        openvzError(VIR_ERR_OPERATION_FAILED,
                    _("Already an OPENVZ VM defined with the id '%s'"),
                   vmdef->name);
        goto cleanup;
    }
    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, vmdef, false)))
        goto cleanup;
    vmdef = NULL;
    /* All OpenVZ domains seem to be persistent - this is a bit of a violation
     * of this libvirt API which is intended for transient domain creation */
    vm->persistent = 1;

    if (openvzSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    openvzSetProgramSentinal(progstart, vm->def->name);

    if (virRun(progstart, NULL) < 0) {
        goto cleanup;
    }

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

    if (vm->def->maxvcpus > 0) {
        if (openvzDomainSetVcpusInternal(vm, vm->def->maxvcpus) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not set number of virtual cpu"));
            goto cleanup;
        }
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virDomainObjUnlock(vm);
    openvzDriverUnlock(driver);
    return dom;
}

static int
openvzDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINAL, NULL };
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dom->name);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching id"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_SHUTOFF) {
        openvzError(VIR_ERR_OPERATION_DENIED, "%s",
                    _("domain is not in shutoff state"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        goto cleanup;
    }

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    dom->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
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
    const char *prog[] = { VZCTL, "--quiet", "destroy", PROGRAM_SENTINAL, NULL };
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        goto cleanup;
    }

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
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINAL,
                           "--onboot", autostart ? "yes" : "no",
                           "--save", NULL };
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
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
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzReadVPSConfigParam(strtoI(vm->def->name), "ONBOOT", &value) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Could not read container config"));
        goto cleanup;
    }

    *autostart = 0;
    if (STREQ(value,"yes"))
        *autostart = 1;
    ret = 0;

cleanup:
    VIR_FREE(value);

    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int openvzGetMaxVCPUs(virConnectPtr conn ATTRIBUTE_UNUSED,
                             const char *type)
{
    if (type == NULL || STRCASEEQ(type, "openvz"))
        return 1028; /* OpenVZ has no limitation */

    openvzError(VIR_ERR_INVALID_ARG,
                _("unknown type '%s'"), type);
    return -1;
}

static int
openvzDomainGetVcpusFlags(virDomainPtr dom ATTRIBUTE_UNUSED,
                          unsigned int flags)
{
    if (flags != (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        openvzError(VIR_ERR_INVALID_ARG, _("unsupported flags (0x%x)"), flags);
        return -1;
    }

    return openvzGetMaxVCPUs(NULL, "openvz");
}

static int openvzDomainGetMaxVcpus(virDomainPtr dom)
{
    return openvzDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                           VIR_DOMAIN_VCPU_MAXIMUM));
}

static int openvzDomainSetVcpusInternal(virDomainObjPtr vm,
                                        unsigned int nvcpus)
{
    char        str_vcpus[32];
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINAL,
                           "--cpus", str_vcpus, "--save", NULL };
    unsigned int pcpus;
    pcpus = openvzGetNodeCPUs();
    if (pcpus > 0 && pcpus < nvcpus)
        nvcpus = pcpus;

    snprintf(str_vcpus, 31, "%d", nvcpus);
    str_vcpus[31] = '\0';

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        return -1;
    }

    vm->def->maxvcpus = vm->def->vcpus = nvcpus;
    return 0;
}

static int openvzDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                                     unsigned int flags)
{
    virDomainObjPtr         vm;
    struct openvz_driver   *driver = dom->conn->privateData;
    int                     ret = -1;

    if (flags != VIR_DOMAIN_AFFECT_LIVE) {
        openvzError(VIR_ERR_INVALID_ARG, _("unsupported flags (0x%x)"), flags);
        return -1;
    }

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (nvcpus <= 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("VCPUs should be >= 1"));
        goto cleanup;
    }

    openvzDomainSetVcpusInternal(vm, nvcpus);
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
openvzDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return openvzDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}

static virDrvOpenStatus openvzOpen(virConnectPtr conn,
                                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
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
            STRNEQ (conn->uri->scheme, "openvz"))
            return VIR_DRV_OPEN_DECLINED;

        /* If server name is given, its for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* If path isn't /system, then they typoed, so tell them correct path */
        if (conn->uri->path == NULL ||
            STRNEQ (conn->uri->path, "/system")) {
            openvzError(VIR_ERR_INTERNAL_ERROR,
                        _("unexpected OpenVZ URI path '%s', try openvz:///system"),
                        conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }

        if (!virFileExists("/proc/vz")) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("OpenVZ control file /proc/vz does not exist"));
            return VIR_DRV_OPEN_ERROR;
        }

        if (access("/proc/vz", W_OK) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("OpenVZ control file /proc/vz is not accessible"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    if (VIR_ALLOC(driver) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }

    if (virDomainObjListInit(&driver->domains) < 0)
        goto cleanup;

    if (!(driver->caps = openvzCapsInit()))
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

static int openvzClose(virConnectPtr conn) {
    struct openvz_driver *driver = conn->privateData;

    openvzFreeDriver(driver);
    conn->privateData = NULL;

    return 0;
}

static const char *openvzGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "OpenVZ";
}

static int openvzIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED) {
    /* Encryption is not relevant / applicable to way we talk to openvz */
    return 0;
}

static int openvzIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED) {
    /* We run CLI tools directly so this is secure */
    return 1;
}

static int
openvzIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static char *openvzGetCapabilities(virConnectPtr conn) {
    struct openvz_driver *driver = conn->privateData;
    char *ret;

    openvzDriverLock(driver);
    ret = virCapabilitiesFormatXML(driver->caps);
    openvzDriverUnlock(driver);

    return ret;
}

static int openvzListDomains(virConnectPtr conn ATTRIBUTE_UNUSED,
                             int *ids, int nids) {
    int got = 0;
    int veid;
    int outfd = -1;
    int rc = -1;
    int ret;
    char buf[32];
    char *endptr;
    virCommandPtr cmd = virCommandNewArgList(VZLIST, "-ovpsid", "-H" , NULL);

    virCommandSetOutputFD(cmd, &outfd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        goto cleanup;

    while (got < nids) {
        ret = openvz_readline(outfd, buf, 32);
        if (!ret)
            break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR,
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

static int openvzNumDomains(virConnectPtr conn) {
    struct openvz_driver *driver = conn->privateData;
    int n;

    openvzDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 1);
    openvzDriverUnlock(driver);

    return n;
}

static int openvzListDefinedDomains(virConnectPtr conn ATTRIBUTE_UNUSED,
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
            openvzError(VIR_ERR_INTERNAL_ERROR,
                        _("Could not parse VPS ID %s"), buf);
            continue;
        }
        snprintf(vpsname, sizeof(vpsname), "%d", veid);
        if (!(names[got] = strdup(vpsname))) {
            virReportOOMError();
            goto out;
        }
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
        for ( ; got >= 0 ; got--)
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

        if (sscanf (line, "%d %llu %llu %llu",
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

static int openvzNumDefinedDomains(virConnectPtr conn) {
    struct openvz_driver *driver =  conn->privateData;
    int n;

    openvzDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 0);
    openvzDriverUnlock(driver);

    return n;
}

static int
openvzDomainSetMemoryInternal(virDomainObjPtr vm,
                              unsigned long long mem)
{
    char str_mem[16];
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINAL,
        "--kmemsize", str_mem, "--save", NULL
    };

    /* memory has to be changed its format from kbyte to byte */
    snprintf(str_mem, sizeof(str_mem), "%llu", mem * 1024);

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        goto cleanup;
    }

    return 0;

cleanup:
    return -1;
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
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
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

static virDriver openvzDriver = {
    .no = VIR_DRV_OPENVZ,
    .name = "OPENVZ",
    .open = openvzOpen, /* 0.3.1 */
    .close = openvzClose, /* 0.3.1 */
    .type = openvzGetType, /* 0.3.1 */
    .version = openvzGetVersion, /* 0.5.0 */
    .getMaxVcpus = openvzGetMaxVCPUs, /* 0.4.6 */
    .nodeGetInfo = nodeGetInfo, /* 0.3.2 */
    .getCapabilities = openvzGetCapabilities, /* 0.4.6 */
    .listDomains = openvzListDomains, /* 0.3.1 */
    .numOfDomains = openvzNumDomains, /* 0.3.1 */
    .domainCreateXML = openvzDomainCreateXML, /* 0.3.3 */
    .domainLookupByID = openvzDomainLookupByID, /* 0.3.1 */
    .domainLookupByUUID = openvzDomainLookupByUUID, /* 0.3.1 */
    .domainLookupByName = openvzDomainLookupByName, /* 0.3.1 */
    .domainSuspend = openvzDomainSuspend, /* 0.8.3 */
    .domainResume = openvzDomainResume, /* 0.8.3 */
    .domainShutdown = openvzDomainShutdown, /* 0.3.1 */
    .domainShutdownFlags = openvzDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = openvzDomainReboot, /* 0.3.1 */
    .domainDestroy = openvzDomainShutdown, /* 0.3.1 */
    .domainDestroyFlags = openvzDomainShutdownFlags, /* 0.9.4 */
    .domainGetOSType = openvzGetOSType, /* 0.3.1 */
    .domainGetInfo = openvzDomainGetInfo, /* 0.3.1 */
    .domainGetState = openvzDomainGetState, /* 0.9.2 */
    .domainSetVcpus = openvzDomainSetVcpus, /* 0.4.6 */
    .domainSetVcpusFlags = openvzDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = openvzDomainGetVcpusFlags, /* 0.8.5 */
    .domainGetMaxVcpus = openvzDomainGetMaxVcpus, /* 0.4.6 */
    .domainGetXMLDesc = openvzDomainGetXMLDesc, /* 0.4.6 */
    .listDefinedDomains = openvzListDefinedDomains, /* 0.3.1 */
    .numOfDefinedDomains = openvzNumDefinedDomains, /* 0.3.1 */
    .domainCreate = openvzDomainCreate, /* 0.3.1 */
    .domainCreateWithFlags = openvzDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = openvzDomainDefineXML, /* 0.3.3 */
    .domainUndefine = openvzDomainUndefine, /* 0.3.3 */
    .domainUndefineFlags = openvzDomainUndefineFlags, /* 0.9.4 */
    .domainGetAutostart = openvzDomainGetAutostart, /* 0.4.6 */
    .domainSetAutostart = openvzDomainSetAutostart, /* 0.4.6 */
    .isEncrypted = openvzIsEncrypted, /* 0.7.3 */
    .isSecure = openvzIsSecure, /* 0.7.3 */
    .domainIsActive = openvzDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = openvzDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = openvzDomainIsUpdated, /* 0.8.6 */
    .isAlive = openvzIsAlive, /* 0.9.8 */
};

int openvzRegister(void) {
    virRegisterDriver(&openvzDriver);
    return 0;
}
