/*
 * openvz_driver.c: core driver methods for managing OpenVZ VEs
 *
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
#include <strings.h>
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
static int openvzDomainSetVcpusInternal(virConnectPtr conn, virDomainObjPtr vm, unsigned int nvcpus);

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
    while(cmdExec[++i])
    {
        VIR_FREE(cmdExec[i]);
    }
}

/* generate arguments to create OpenVZ container
   return -1 - error
           0 - OK
*/
static int openvzDomainDefineCmd(virConnectPtr conn,
                                 const char *args[],
                                 int maxarg,
                                 virDomainDefPtr vmdef)
{
    int narg;

    for (narg = 0; narg < maxarg; narg++)
        args[narg] = NULL;

    if (vmdef == NULL){
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Container is not defined"));
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

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_TEMPLATE)
    {
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
    openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                _("Could not put argument to %s"), VZCTL);
    return -1;
#undef ADD_ARG
#undef ADD_ARG_LIT
}


static int openvzSetInitialConfig(virConnectPtr conn,
                                  virDomainDefPtr vmdef)
{
    int ret = -1;
    int vpsid;
    char * confdir = NULL;
    const char *prog[OPENVZ_MAX_ARG];
    prog[0] = NULL;

    if (vmdef->nfss > 1) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("only one filesystem supported"));
        goto cleanup;
    }

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_TEMPLATE &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
    {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("filesystem is not of type 'template' or 'mount'"));
        goto cleanup;
    }


    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_MOUNT)
    {

        if(virStrToLong_i(vmdef->name, NULL, 10, &vpsid) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Could not convert domain name to VEID"));
            goto cleanup;
        }

        if (openvzCopyDefaultConfig(vpsid) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Could not copy default config"));
            goto cleanup;
        }

        if (openvzWriteVPSConfigParam(vpsid, "VE_PRIVATE", vmdef->fss[0]->src) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Could not set the source dir for the filesystem"));
            goto cleanup;
        }
    }
    else
    {
        if (openvzDomainDefineCmd(conn, prog, OPENVZ_MAX_ARG, vmdef) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Error creating command for container"));
            goto cleanup;
        }

        if (virRun(conn, prog, NULL) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
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
        openvzError(conn, VIR_ERR_NO_DOMAIN, NULL);
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
        openvzError(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (!(ret = strdup(vm->def->os.type)))
        virReportOOMError(dom->conn);

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
        openvzError(conn, VIR_ERR_NO_DOMAIN, NULL);
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
        openvzError(conn, VIR_ERR_NO_DOMAIN, NULL);
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
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (openvzGetProcessInfo(&(info->cpuTime), dom->id) < 0) {
            openvzError(dom->conn, VIR_ERR_OPERATION_FAILED,
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


static char *openvzDomainDumpXML(virDomainPtr dom, int flags) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(dom->conn, vm->def, flags);

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

static int openvzDomainShutdown(virDomainPtr dom) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "stop", PROGRAM_SENTINAL, NULL};
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (vm->state != VIR_DOMAIN_RUNNING) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(dom->conn, prog, NULL) < 0)
        goto cleanup;

    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;
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
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (vm->state != VIR_DOMAIN_RUNNING) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(dom->conn, prog, NULL) < 0)
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
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Container ID is not specified"));
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

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        char *dev_name_ve;
        int veid = strtoI(vpsid);

        //--netif_add ifname[,mac,host_ifname,host_mac]
        ADD_ARG_LIT("--netif_add") ;

        /* generate interface name in ve and copy it to options */
        dev_name_ve = openvzGenerateContainerVethName(veid);
        if (dev_name_ve == NULL) {
           openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Could not generate eth name for container"));
           rc = -1;
           goto exit;
        }

        /* if user doesn't specified host interface name,
         * than we need to generate it */
        if (net->ifname == NULL) {
            net->ifname = openvzGenerateVethName(veid, dev_name_ve);
            if (net->ifname == NULL) {
               openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Could not generate veth name"));
               rc = -1;
               VIR_FREE(dev_name_ve);
               goto exit;
            }
        }

        virBufferAdd(&buf, dev_name_ve, -1); /* Guest dev */
        virBufferVSprintf(&buf, ",%s", macaddr); /* Guest dev mac */
        virBufferVSprintf(&buf, ",%s", net->ifname); /* Host dev */
        virBufferVSprintf(&buf, ",%s", host_macaddr); /* Host dev mac */

        if (driver->version >= VZCTL_BRIDGE_MIN_VERSION) {
            virBufferVSprintf(&buf, ",%s", net->data.bridge.brname); /* Host bridge */
        } else {
            virBufferVSprintf(configBuf, "ifname=%s", dev_name_ve);
            virBufferVSprintf(configBuf, ",mac=%s", macaddr); /* Guest dev mac */
            virBufferVSprintf(configBuf, ",host_ifname=%s", net->ifname); /* Host dev */
            virBufferVSprintf(configBuf, ",host_mac=%s", host_macaddr); /* Host dev mac */
            virBufferVSprintf(configBuf, ",bridge=%s", net->data.bridge.brname); /* Host bridge */
        }

        VIR_FREE(dev_name_ve);

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

    if (prog[0] != NULL){
        ADD_ARG_LIT("--save");
        if (virRun(conn, prog, NULL) < 0) {
           openvzError(conn, VIR_ERR_INTERNAL_ERROR,
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
    openvzError(conn, VIR_ERR_INTERNAL_ERROR,
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
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Could not configure network"));
            goto exit;
        }
    }

    if (driver->version < VZCTL_BRIDGE_MIN_VERSION && def->nnets) {
        param = virBufferContentAndReset(&buf);
        if (param) {
            if (openvzWriteVPSConfigParam(strtoI(def->name), "NETIF", param) < 0) {
                VIR_FREE(param);
                openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("cannot replace NETIF config"));
                return -1;
            }
            VIR_FREE(param);
        }
    }

    return 0;

exit:
    param = virBufferContentAndReset(&buf);
    VIR_FREE(param);
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
    if ((vmdef = virDomainDefParseString(conn, driver->caps, xml,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (vmdef->os.init == NULL &&
        !(vmdef->os.init = strdup("/sbin/init"))) {
        goto cleanup;
    }

    vm = virDomainFindByName(&driver->domains, vmdef->name);
    if (vm) {
        openvzError(conn, VIR_ERR_OPERATION_FAILED,
                  _("Already an OPENVZ VM active with the id '%s'"),
                  vmdef->name);
        goto cleanup;
    }
    if (!(vm = virDomainAssignDef(conn, &driver->domains, vmdef)))
        goto cleanup;
    vmdef = NULL;

    if (openvzSetInitialConfig(conn, vm->def) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                "%s", _("Error creating intial configuration"));
        goto cleanup;
    }

    //TODO: set quota

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               "%s", _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    if (vm->def->vcpus > 0) {
        if (openvzDomainSetVcpusInternal(conn, vm, vm->def->vcpus) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                     "%s", _("Could not set number of virtual cpu"));
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
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    struct openvz_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    const char *progstart[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINAL, NULL};

    openvzDriverLock(driver);
    if ((vmdef = virDomainDefParseString(conn, driver->caps, xml,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (vmdef->os.init == NULL &&
        !(vmdef->os.init = strdup("/sbin/init")))
        goto cleanup;

    vm = virDomainFindByName(&driver->domains, vmdef->name);
    if (vm) {
        openvzError(conn, VIR_ERR_OPERATION_FAILED,
                  _("Already an OPENVZ VM defined with the id '%s'"),
                  vmdef->name);
        goto cleanup;
    }
    if (!(vm = virDomainAssignDef(conn, &driver->domains, vmdef)))
        goto cleanup;
    vmdef = NULL;

    if (openvzSetInitialConfig(conn, vm->def) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                "%s", _("Error creating intial configuration"));
        goto cleanup;
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               "%s", _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    openvzSetProgramSentinal(progstart, vm->def->name);

    if (virRun(conn, progstart, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZCTL);
        goto cleanup;
    }

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;

    if (vm->def->vcpus > 0) {
        if (openvzDomainSetVcpusInternal(conn, vm, vm->def->vcpus) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Could not set number of virtual cpu"));
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
openvzDomainCreate(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINAL, NULL };
    int ret = -1;

    openvzDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dom->name);
    openvzDriverUnlock(driver);

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    "%s", _("no domain with matching id"));
        goto cleanup;
    }

    if (vm->state != VIR_DOMAIN_SHUTOFF) {
        openvzError(dom->conn, VIR_ERR_OPERATION_DENIED,
                    "%s", _("domain is not in shutoff state"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(dom->conn, prog, NULL) < 0) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZCTL);
        goto cleanup;
    }

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
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
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR, "%s", _("cannot delete active domain"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(dom->conn, prog, NULL) < 0) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
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
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
    if (virRun(dom->conn, prog, NULL) < 0) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR, _("Could not exec %s"), VZCTL);
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
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openvzReadVPSConfigParam(strtoI(vm->def->name), "ONBOOT", value, sizeof(value)) < 0) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Could not read container config"));
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

static int openvzGetMaxVCPUs(virConnectPtr conn, const char *type)
{
    if (type == NULL || STRCASEEQ(type, "openvz"))
        return 1028; /* OpenVZ has no limitation */

    openvzError(conn, VIR_ERR_INVALID_ARG,
                     _("unknown type '%s'"), type);
    return -1;
}


static int openvzDomainGetMaxVcpus(virDomainPtr dom) {
    return openvzGetMaxVCPUs(dom->conn, "openvz");
}

static int openvzDomainSetVcpusInternal(virConnectPtr conn, virDomainObjPtr vm,
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
    if (virRun(conn, prog, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
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
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (nvcpus <= 0) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("VCPUs should be >= 1"));
        goto cleanup;
    }

    openvzDomainSetVcpusInternal(dom->conn, vm, nvcpus);
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
            virReportOOMError(conn);
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
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        _("unexpected OpenVZ URI path '%s', try openvz:///system"),
                        conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }

        if (!virFileExists("/proc/vz")) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                        _("OpenVZ control file /proc/vz does not exist"));
            return VIR_DRV_OPEN_ERROR;
        }

        if (access("/proc/vz", W_OK) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                        _("OpenVZ control file /proc/vz is not accessible"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    if (VIR_ALLOC(driver) < 0) {
        virReportOOMError(conn);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!(driver->caps = openvzCapsInit()))
        goto cleanup;

    if (openvzLoadDomains(driver) < 0)
        goto cleanup;

    if (openvzExtractVersion(conn, driver) < 0)
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

static char *openvzGetCapabilities(virConnectPtr conn) {
    struct openvz_driver *driver = conn->privateData;
    char *ret;

    openvzDriverLock(driver);
    ret = virCapabilitiesFormatXML(driver->caps);
    openvzDriverUnlock(driver);

    return ret;
}

static int openvzListDomains(virConnectPtr conn, int *ids, int nids) {
    int got = 0;
    int veid;
    pid_t pid;
    int outfd = -1;
    int errfd = -1;
    int ret;
    char buf[32];
    char *endptr;
    const char *cmd[] = {VZLIST, "-ovpsid", "-H" , NULL};

    ret = virExec(conn, cmd, NULL, NULL,
                  &pid, -1, &outfd, &errfd, VIR_EXEC_NONE);
    if(ret == -1) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZLIST);
        return -1;
    }

    while(got < nids){
        ret = openvz_readline(outfd, buf, 32);
        if(!ret) break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
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
    int nactive = 0, i;

    openvzDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (virDomainIsActive(driver->domains.objs[i]))
            nactive++;
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    openvzDriverUnlock(driver);

    return nactive;
}

static int openvzListDefinedDomains(virConnectPtr conn,
                                    char **const names, int nnames) {
    int got = 0;
    int veid, outfd = -1, errfd = -1, ret;
    pid_t pid;
    char vpsname[32];
    char buf[32];
    char *endptr;
    const char *cmd[] = {VZLIST, "-ovpsid", "-H", "-S", NULL};

    /* the -S options lists only stopped domains */
    ret = virExec(conn, cmd, NULL, NULL,
                  &pid, -1, &outfd, &errfd, VIR_EXEC_NONE);
    if(ret == -1) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZLIST);
        return -1;
    }

    while(got < nnames){
        ret = openvz_readline(outfd, buf, 32);
        if(!ret) break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
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
    virReportOOMError(conn);
    for ( ; got >= 0 ; got--)
        VIR_FREE(names[got]);
    return -1;
}

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid) {
    int fd;
    char line[1024] ;
    unsigned long long usertime, systime, nicetime;
    int readvps = 0, ret;

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
    while(1) {
        ret = openvz_readline(fd, line, sizeof(line));
        if(ret <= 0)
            break;

        if (sscanf(line, "%d %llu %llu %llu",
                          &readvps, &usertime, &nicetime, &systime) != 4)
            continue;

        if (readvps == vpsid)
            break; /*found vpsid*/
    }

    close(fd);
    if (ret < 0)
        return -1;

    if (readvps != vpsid) /*not found*/
        return -1;

    /* convert jiffies to nanoseconds */
    *cpuTime = 1000ull * 1000ull * 1000ull * (usertime + nicetime  + systime)
                                     / (unsigned long long)sysconf(_SC_CLK_TCK);

    return 0;
}

static int openvzNumDefinedDomains(virConnectPtr conn) {
    struct openvz_driver *driver =  conn->privateData;
    int ninactive = 0, i;

    openvzDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (!virDomainIsActive(driver->domains.objs[i]))
            ninactive++;
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    openvzDriverUnlock(driver);

    return ninactive;
}

static virDriver openvzDriver = {
    VIR_DRV_OPENVZ,
    "OPENVZ",
    openvzOpen, /* open */
    openvzClose, /* close */
    NULL, /* supports_feature */
    openvzGetType, /* type */
    openvzGetVersion, /* version */
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
    NULL, /* domainSuspend */
    NULL, /* domainResume */
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
    openvzDomainDefineXML, /* domainDefineXML */
    openvzDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
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
    NULL, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    NULL, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
    NULL, /* domainEventRegister */
    NULL, /* domainEventDeregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
    NULL, /* nodeDeviceDettach */
    NULL, /* nodeDeviceReAttach */
    NULL, /* nodeDeviceReset */
};

int openvzRegister(void) {
    virRegisterDriver(&openvzDriver);
    return 0;
}
