/*
 * openvz_driver.c: core driver methods for managing OpenVZ VEs
 *
 * Copyright (C) 2010 Red Hat, Inc.
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
#include <dirent.h>
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
#include <signal.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "openvz_driver.h"
#include "event.h"
#include "buf.h"
#include "util.h"
#include "openvz_conf.h"
#include "nodeinfo.h"
#include "memory.h"
#include "bridge.h"

#define VIR_FROM_THIS VIR_FROM_OPENVZ

#define OPENVZ_MAX_ARG 28
#define CMDBUF_LEN 1488
#define CMDOP_LEN 288

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid);
static int openvzGetMaxVCPUs(virConnectPtr conn, const char *type);
static int openvzDomainGetMaxVcpus(virDomainPtr dom);
static int openvzDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus);
static int openvzDomainSetVcpusInternal(virDomainObjPtr vm,
                                        unsigned int nvcpus);
static int openvzDomainSetMemoryInternal(virDomainObjPtr vm,
                                         unsigned long memory);

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
    int veid;
    int max_veid;
    char str_id[10];
    FILE *fp;

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

    if ((fp = popen(VZLIST " -a -ovpsid -H 2>/dev/null", "r")) == NULL) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("popen  failed"));
        return -1;
    }
    max_veid = 0;
    while (!feof(fp)) {
        if (fscanf(fp, "%d\n", &veid) != 1) {
            if (feof(fp))
                break;

            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to parse vzlist output"));
            goto cleanup;
        }
        if (veid > max_veid) {
            max_veid = veid;
        }
    }
    fclose(fp);

    if (max_veid == 0) {
        max_veid = 100;
    } else {
        max_veid++;
    }

    sprintf(str_id, "%d", max_veid);
    ADD_ARG_LIT(str_id);

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

cleanup:
    fclose(fp);
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
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Error creating command for container"));
            goto cleanup;
        }

        if (virRun(prog, NULL) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR,
                        _("Could not exec %s"), VZCTL);
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
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    info->state = vm->state;

    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (openvzGetProcessInfo(&(info->cpuTime), dom->id) < 0) {
            openvzError(VIR_ERR_OPERATION_FAILED,
                        _("cannot read cputime for domain %d"), dom->id);
            goto cleanup;
        }
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

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


static char *openvzDomainDumpXML(virDomainPtr dom, int flags) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
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
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        openvzError(VIR_ERR_OPERATION_INVALID, "%s",
                    _("Domain is not running"));
        goto cleanup;
    }

    if (vm->state != VIR_DOMAIN_PAUSED) {
        openvzSetProgramSentinal(prog, vm->def->name);
        if (virRun(prog, NULL) < 0) {
            openvzError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("Suspend operation failed"));
            goto cleanup;
        }
        vm->state = VIR_DOMAIN_PAUSED;
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
      openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                  _("no domain with matching uuid"));
      goto cleanup;
  }

  if (!virDomainObjIsActive(vm)) {
      openvzError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not running"));
      goto cleanup;
  }

  if (vm->state == VIR_DOMAIN_PAUSED) {
      openvzSetProgramSentinal(prog, vm->def->name);
      if (virRun(prog, NULL) < 0) {
          openvzError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("Resume operation failed"));
          goto cleanup;
      }
      vm->state = VIR_DOMAIN_RUNNING;
  }

  ret = 0;

cleanup:
  if (vm)
      virDomainObjUnlock(vm);
  return ret;
}

static int openvzDomainShutdown(virDomainPtr dom) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "stop", PROGRAM_SENTINAL, NULL};
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (vm->state != VIR_DOMAIN_RUNNING) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(prog, NULL) < 0)
        goto cleanup;

    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;
    dom->id = -1;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int openvzDomainReboot(virDomainPtr dom,
                              unsigned int flags ATTRIBUTE_UNUSED) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "restart", PROGRAM_SENTINAL, NULL};
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (vm->state != VIR_DOMAIN_RUNNING) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(prog, NULL) < 0)
        goto cleanup;
    ret = 0;

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
    char    temp[1024];

    /* try to get line "^NETIF=..." from config */
    if (openvzReadVPSConfigParam(veid, "NETIF", temp, sizeof(temp)) <= 0) {
        snprintf(temp, sizeof(temp), "eth0");
    } else {
        char *saveptr;
        char   *s;
        int     max = 0;

        /* get maximum interface number (actually, it is the last one) */
        for (s=strtok_r(temp, ";", &saveptr); s; s=strtok_r(NULL, ";", &saveptr)) {
            int x;

            if (sscanf(s, "ifname=eth%d", &x) != 1) return NULL;
            if (x > max) max = x;
        }

        /* set new name */
        snprintf(temp, sizeof(temp), "eth%d", max+1);
    }
    return strdup(temp);
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

    virFormatMacAddr(net->mac, macaddr);
    virCapabilitiesGenerateMac(driver->caps, host_mac);
    virFormatMacAddr(host_mac, host_macaddr);

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
         net->data.ethernet.ipaddr == NULL)) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        int veid = openvzGetVEID(vpsid);

        //--netif_add ifname[,mac,host_ifname,host_mac]
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
        virBufferVSprintf(&buf, ",%s", macaddr); /* Guest dev mac */
        virBufferVSprintf(&buf, ",%s", net->ifname); /* Host dev */
        virBufferVSprintf(&buf, ",%s", host_macaddr); /* Host dev mac */

        if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (driver->version >= VZCTL_BRIDGE_MIN_VERSION) {
                virBufferVSprintf(&buf, ",%s", net->data.bridge.brname); /* Host bridge */
            } else {
                virBufferVSprintf(configBuf, "ifname=%s", net->data.ethernet.dev);
                virBufferVSprintf(configBuf, ",mac=%s", macaddr); /* Guest dev mac */
                virBufferVSprintf(configBuf, ",host_ifname=%s", net->ifname); /* Host dev */
                virBufferVSprintf(configBuf, ",host_mac=%s", host_macaddr); /* Host dev mac */
                virBufferVSprintf(configBuf, ",bridge=%s", net->data.bridge.brname); /* Host bridge */
            }
        }

        if (!(opt = virBufferContentAndReset(&buf)))
            goto no_memory;

        ADD_ARG_LIT(opt) ;
        VIR_FREE(opt);
    } else if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
              net->data.ethernet.ipaddr != NULL) {
        //--ipadd ip
        ADD_ARG_LIT("--ipadd") ;
        ADD_ARG_LIT(net->data.ethernet.ipaddr) ;
    }

    //TODO: processing NAT and physical device

    if (prog[0] != NULL) {
        ADD_ARG_LIT("--save");
        if (virRun(prog, NULL) < 0) {
           openvzError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not exec %s"), VZCTL);
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
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (vmdef->os.init == NULL) {
        if (!(vmdef->os.init = strdup("/sbin/init"))) {
            virReportOOMError();
            goto cleanup;
        }
    }

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
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Error creating initial configuration"));
        goto cleanup;
    }

    //TODO: set quota

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    if (vm->def->vcpus > 0) {
        if (openvzDomainSetVcpusInternal(vm, vm->def->vcpus) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not set number of virtual cpu"));
             goto cleanup;
        }
    }

    if (vm->def->memory > 0) {
        if (openvzDomainSetMemoryInternal(vm, vm->def->memory) < 0) {
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
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (vmdef->os.init == NULL) {
        if (!(vmdef->os.init = strdup("/sbin/init"))) {
            virReportOOMError();
            goto cleanup;
        }
    }

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
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Error creating initial configuration"));
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
        openvzError(VIR_ERR_INTERNAL_ERROR,
                   _("Could not exec %s"), VZCTL);
        goto cleanup;
    }

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;

    if (vm->def->vcpus > 0) {
        if (openvzDomainSetVcpusInternal(vm, vm->def->vcpus) < 0) {
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

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dom->name);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching id"));
        goto cleanup;
    }

    if (vm->state != VIR_DOMAIN_SHUTOFF) {
        openvzError(VIR_ERR_OPERATION_DENIED, "%s",
                    _("domain is not in shutoff state"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZCTL);
        goto cleanup;
    }

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    dom->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;
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
openvzDomainUndefine(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = { VZCTL, "--quiet", "destroy", PROGRAM_SENTINAL, NULL };
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot delete active domain"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZCTL);
        goto cleanup;
    }

    virDomainRemoveInactive(&driver->domains, vm);
    vm = NULL;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    openvzDriverUnlock(driver);
    return ret;
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
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZCTL);
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
    char value[1024];
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzReadVPSConfigParam(strtoI(vm->def->name), "ONBOOT", value, sizeof(value)) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Could not read container config"));
        goto cleanup;
    }

    *autostart = 0;
    if (STREQ(value,"yes"))
        *autostart = 1;
    ret = 0;

cleanup:
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


static int openvzDomainGetMaxVcpus(virDomainPtr dom ATTRIBUTE_UNUSED) {
    return openvzGetMaxVCPUs(NULL, "openvz");
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
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZCTL);
        return -1;
    }

    vm->def->vcpus = nvcpus;
    return 0;
}

static int openvzDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    virDomainObjPtr         vm;
    struct openvz_driver   *driver = dom->conn->privateData;
    int                     ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(VIR_ERR_INVALID_DOMAIN, "%s",
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

static virDrvOpenStatus openvzOpen(virConnectPtr conn,
                                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                   int flags ATTRIBUTE_UNUSED)
{
    struct openvz_driver *driver;

    if (conn->uri == NULL) {
        if (!virFileExists("/proc/vz"))
            return VIR_DRV_OPEN_DECLINED;

        if (access("/proc/vz", W_OK) < 0)
            return VIR_DRV_OPEN_DECLINED;

        conn->uri = xmlParseURI("openvz:///system");
        if (conn->uri == NULL) {
            virReportOOMError();
            return VIR_DRV_OPEN_ERROR;
        }
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
    pid_t pid;
    int outfd = -1;
    int errfd = -1;
    int ret;
    char buf[32];
    char *endptr;
    const char *cmd[] = {VZLIST, "-ovpsid", "-H" , NULL};

    ret = virExec(cmd, NULL, NULL,
                  &pid, -1, &outfd, &errfd, VIR_EXEC_NONE);
    if (ret == -1) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZLIST);
        return -1;
    }

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
    waitpid(pid, NULL, 0);

    return got;
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
    int veid, outfd = -1, errfd = -1, ret;
    pid_t pid;
    char vpsname[32];
    char buf[32];
    char *endptr;
    const char *cmd[] = {VZLIST, "-ovpsid", "-H", "-S", NULL};

    /* the -S options lists only stopped domains */
    ret = virExec(cmd, NULL, NULL,
                  &pid, -1, &outfd, &errfd, VIR_EXEC_NONE);
    if (ret == -1) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZLIST);
        return -1;
    }

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
        if (!(names[got] = strdup(vpsname)))
            goto no_memory;
        got ++;
    }
    waitpid(pid, NULL, 0);
    return got;

no_memory:
    virReportOOMError();
    for ( ; got >= 0 ; got--)
        VIR_FREE(names[got]);
    return -1;
}

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid) {
    int fd;
    char line[1024] ;
    unsigned long long usertime, systime, nicetime;
    int readvps = vpsid + 1;  /* ensure readvps is initially different */
    int ret;

/* read statistic from /proc/vz/vestat.
sample:
Version: 2.2
   VEID     user      nice     system     uptime                 idle   other..
     33       78         0       1330   59454597      142650441835148   other..
     55      178         0       5340   59424597      542650441835148   other..
*/

    if ((fd = open("/proc/vz/vestat", O_RDONLY)) == -1)
        return -1;

    /*search line with VEID=vpsid*/
    while (1) {
        ret = openvz_readline(fd, line, sizeof(line));
        if (ret <= 0)
            break;

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

    close(fd);
    if (ret < 0)
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
                              unsigned long mem)
{
    char str_mem[16];
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINAL,
        "--kmemsize", str_mem, "--save", NULL
    };

    /* memory has to be changed its format from kbyte to byte */
    snprintf(str_mem, sizeof(str_mem), "%lu", mem * 1024);

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZCTL);
        goto cleanup;
    }

    return 0;

cleanup:
    return -1;
}

static virDriver openvzDriver = {
    VIR_DRV_OPENVZ,
    "OPENVZ",
    openvzOpen, /* open */
    openvzClose, /* close */
    NULL, /* supports_feature */
    openvzGetType, /* type */
    openvzGetVersion, /* version */
    NULL, /* libvirtVersion (impl. in libvirt.c) */
    NULL, /* getHostname */
    openvzGetMaxVCPUs, /* getMaxVcpus */
    nodeGetInfo, /* nodeGetInfo */
    openvzGetCapabilities, /* getCapabilities */
    openvzListDomains, /* listDomains */
    openvzNumDomains, /* numOfDomains */
    openvzDomainCreateXML, /* domainCreateXML */
    openvzDomainLookupByID, /* domainLookupByID */
    openvzDomainLookupByUUID, /* domainLookupByUUID */
    openvzDomainLookupByName, /* domainLookupByName */
    openvzDomainSuspend, /* domainSuspend */
    openvzDomainResume, /* domainResume */
    openvzDomainShutdown, /* domainShutdown */
    openvzDomainReboot, /* domainReboot */
    openvzDomainShutdown, /* domainDestroy */
    openvzGetOSType, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    openvzDomainGetInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
    openvzDomainSetVcpus, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    openvzDomainGetMaxVcpus, /* domainGetMaxVcpus */
    NULL, /* domainGetSecurityLabel */
    NULL, /* nodeGetSecurityModel */
    openvzDomainDumpXML, /* domainDumpXML */
    NULL, /* domainXmlFromNative */
    NULL, /* domainXmlToNative */
    openvzListDefinedDomains, /* listDefinedDomains */
    openvzNumDefinedDomains, /* numOfDefinedDomains */
    openvzDomainCreate, /* domainCreate */
    openvzDomainCreateWithFlags, /* domainCreateWithFlags */
    openvzDomainDefineXML, /* domainDefineXML */
    openvzDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainAttachDeviceFlags */
    NULL, /* domainDetachDevice */
    NULL, /* domainDetachDeviceFlags */
    NULL, /* domainUpdateDeviceFlags */
    openvzDomainGetAutostart, /* domainGetAutostart */
    openvzDomainSetAutostart, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare */
    NULL, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    NULL, /* domainBlockStats */
    NULL, /* domainInterfaceStats */
    NULL, /* domainMemoryStats */
    NULL, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    NULL, /* domainGetBlockInfo */
    NULL, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
    NULL, /* domainEventRegister */
    NULL, /* domainEventDeregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
    NULL, /* nodeDeviceDettach */
    NULL, /* nodeDeviceReAttach */
    NULL, /* nodeDeviceReset */
    NULL, /* domainMigratePrepareTunnel */
    openvzIsEncrypted,
    openvzIsSecure,
    openvzDomainIsActive,
    openvzDomainIsPersistent,
    NULL, /* cpuCompare */
    NULL, /* cpuBaseline */
    NULL, /* domainGetJobInfo */
    NULL, /* domainAbortJob */
    NULL, /* domainMigrateSetMaxDowntime */
    NULL, /* domainEventRegisterAny */
    NULL, /* domainEventDeregisterAny */
    NULL, /* domainManagedSave */
    NULL, /* domainHasManagedSaveImage */
    NULL, /* domainManagedSaveRemove */
    NULL, /* domainSnapshotCreateXML */
    NULL, /* domainSnapshotDumpXML */
    NULL, /* domainSnapshotNum */
    NULL, /* domainSnapshotListNames */
    NULL, /* domainSnapshotLookupByName */
    NULL, /* domainHasCurrentSnapshot */
    NULL, /* domainSnapshotCurrent */
    NULL, /* domainRevertToSnapshot */
    NULL, /* domainSnapshotDelete */
    NULL, /* qemuDomainMonitorCommand */
};

int openvzRegister(void) {
    virRegisterDriver(&openvzDriver);
    return 0;
}
