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

#include "internal.h"
#include "openvz_driver.h"
#include "event.h"
#include "buf.h"
#include "util.h"
#include "openvz_conf.h"
#include "nodeinfo.h"
#include "memory.h"

#define OPENVZ_MAX_ARG 28
#define CMDBUF_LEN 1488
#define CMDOP_LEN 288

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid);
static int openvzGetMaxVCPUs(virConnectPtr conn, const char *type);
static int openvzDomainGetMaxVcpus(virDomainPtr dom);
static int openvzDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus);

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

    if (vmdef->fss) {
        if (vmdef->fss->type != VIR_DOMAIN_FS_TYPE_TEMPLATE) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("only filesystem templates are supported"));
            return -1;
        }

        if (vmdef->fss->next) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("only one filesystem supported"));
            return -1;
        }

        ADD_ARG_LIT("--ostemplate");
        ADD_ARG_LIT(vmdef->fss->src);
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


static virDomainPtr openvzDomainLookupByID(virConnectPtr conn,
                                           int id) {
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom;

    vm = virDomainFindByID(driver->domains, id);

    if (!vm) {
        openvzError(conn, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (!dom)
        return NULL;

    dom->id = vm->def->id;
    return dom;
}

static char *openvzGetOSType(virDomainPtr dom)
{
    struct  openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    char *ret;

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    if (!(ret = strdup(vm->def->os.type)))
        openvzError(dom->conn, VIR_ERR_NO_MEMORY, NULL);

    return ret;
}


static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid) {
    struct  openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, uuid);
    virDomainPtr dom;

    if (!vm) {
        openvzError(conn, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (!dom)
        return NULL;

    dom->id = vm->def->id;
    return dom;
}

static virDomainPtr openvzDomainLookupByName(virConnectPtr conn,
                                     const char *name) {
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByName(driver->domains, name);
    virDomainPtr dom;

    if (!vm) {
        openvzError(conn, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (!dom)
        return NULL;

    dom->id = vm->def->id;
    return dom;
}

static int openvzDomainGetInfo(virDomainPtr dom,
                               virDomainInfoPtr info) {
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    _("no domain with matching uuid"));
        return -1;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (openvzGetProcessInfo(&(info->cpuTime), dom->id) < 0) {
            openvzError(dom->conn, VIR_ERR_OPERATION_FAILED,
                        _("cannot read cputime for domain %d"), dom->id);
            return -1;
        }
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = vm->def->vcpus;
    return 0;
}


static char *openvzDomainDumpXML(virDomainPtr dom, int flags) {
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    _("no domain with matching uuid"));
        return NULL;
    }

    return virDomainDefFormat(dom->conn, vm->def, flags);
}



static int openvzDomainShutdown(virDomainPtr dom) {
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    const char *prog[] = {VZCTL, "--quiet", "stop", vm ? vm->def->name : NULL, NULL};

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    _("no domain with matching uuid"));
        return -1;
    }

    if (vm->state != VIR_DOMAIN_RUNNING) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
                    _("domain is not in running state"));
        return -1;
    }

    if (virRun(dom->conn, prog, NULL) < 0)
        return -1;

    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;

    return 0;
}

static int openvzDomainReboot(virDomainPtr dom,
                              unsigned int flags ATTRIBUTE_UNUSED) {
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    const char *prog[] = {VZCTL, "--quiet", "restart", vm ? vm->def->name : NULL, NULL};

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
                    _("no domain with matching uuid"));
        return -1;
    }

    if (vm->state != VIR_DOMAIN_RUNNING) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
                    _("domain is not in running state"));
        return -1;
    }

    if (virRun(dom->conn, prog, NULL) < 0)
        return -1;

    return 0;
}

static int
openvzDomainSetNetwork(virConnectPtr conn, const char *vpsid,
                        virDomainNetDefPtr net)
{
    int rc = 0, narg;
    const char *prog[OPENVZ_MAX_ARG];
    char *mac = NULL;

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

    if (openvzCheckEmptyMac(net->mac) > 0)
          mac = openvzMacToString(net->mac);

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE &&
           net->data.bridge.brname != NULL) {
        char opt[1024];
        //--netif_add ifname[,mac,host_ifname,host_mac]
        ADD_ARG_LIT("--netif_add") ;
        strncpy(opt, net->data.bridge.brname, 256);
        if (mac != NULL) {
            strcat(opt, ",");
            strcat(opt, mac);
        }
        ADD_ARG_LIT(opt) ;
    }else if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
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

    if (net->next != NULL)
       if (openvzDomainSetNetwork(conn, vpsid, net->next) < 0) {
          rc = -1;
          goto exit;
       }

 exit:
    cmdExecFree(prog);
    VIR_FREE(mac);
    return rc;

 no_memory:
    openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                _("Could not put argument to %s"), VZCTL);
    cmdExecFree(prog);
    VIR_FREE(mac);
    return -1;

#undef ADD_ARG_LIT
}

static virDomainPtr
openvzDomainDefineXML(virConnectPtr conn, const char *xml)
{
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    const char *prog[OPENVZ_MAX_ARG];
    prog[0] = NULL;

    if ((vmdef = virDomainDefParseString(conn, driver->caps, xml)) == NULL)
        return NULL;

    if (vmdef->os.init == NULL &&
        !(vmdef->os.init = strdup("/sbin/init"))) {
        virDomainDefFree(vmdef);
        return NULL;
    }

    vm = virDomainFindByName(driver->domains, vmdef->name);
    if (vm) {
        openvzError(conn, VIR_ERR_OPERATION_FAILED,
                  _("Already an OPENVZ VM active with the id '%s'"),
                  vmdef->name);
        virDomainDefFree(vmdef);
        return NULL;
    }
    if (!(vm = virDomainAssignDef(conn, &driver->domains, vmdef))) {
        virDomainDefFree(vmdef);
        return NULL;
    }

    if (openvzDomainDefineCmd(conn, prog, OPENVZ_MAX_ARG, vmdef) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                _("Error creating command for container"));
        goto exit;
    }

    //TODO: set quota

    if (virRun(conn, prog, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZCTL);
        goto exit;
    }

    if (openvzSetDefinedUUID(strtoI(vmdef->name), vmdef->uuid) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not set UUID"));
        goto exit;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = -1;

    if (openvzDomainSetNetwork(conn, vmdef->name, vmdef->nets) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                  _("Could not configure network"));
        goto exit;
    }

    if (vmdef->vcpus > 0) {
        if (openvzDomainSetVcpus(dom, vmdef->vcpus) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("Could not set number of virtual cpu"));
             goto exit;
        }
    }

    exit:
    cmdExecFree(prog);
    return dom;
}

static virDomainPtr
openvzDomainCreateLinux(virConnectPtr conn, const char *xml,
                        unsigned int flags ATTRIBUTE_UNUSED)
{
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    const char *progstart[] = {VZCTL, "--quiet", "start", NULL, NULL};
    const char *progcreate[OPENVZ_MAX_ARG];
    progcreate[0] = NULL;

    if ((vmdef = virDomainDefParseString(conn, driver->caps, xml)) == NULL)
        return NULL;

    if (vmdef->os.init == NULL &&
        !(vmdef->os.init = strdup("/sbin/init"))) {
        virDomainDefFree(vmdef);
        return NULL;
    }

    vm = virDomainFindByName(driver->domains, vmdef->name);
    if (vm) {
        openvzError(conn, VIR_ERR_OPERATION_FAILED,
                  _("Already an OPENVZ VM defined with the id '%s'"),
                  vmdef->name);
        virDomainDefFree(vmdef);
        return NULL;
    }
    if (!(vm = virDomainAssignDef(conn, &driver->domains, vmdef))) {
        virDomainDefFree(vmdef);
        return NULL;
    }

    if (openvzDomainDefineCmd(conn, progcreate, OPENVZ_MAX_ARG, vmdef) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                _("Error creating command for container"));
        goto exit;
    }

    if (virRun(conn, progcreate, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZCTL);
        goto exit;
    }

    if (openvzSetDefinedUUID(strtoI(vmdef->name), vmdef->uuid) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not set UUID"));
        goto exit;
    }

    if (openvzDomainSetNetwork(conn, vmdef->name, vmdef->nets) < 0) {
       openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                  _("Could not configure network"));
        goto exit;
    }

    progstart[3] = vmdef->name;

    if (virRun(conn, progstart, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZCTL);
        goto exit;
    }

    vm->pid = strtoI(vmdef->name);
    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    if (vmdef->vcpus > 0) {
        if (openvzDomainSetVcpus(dom, vmdef->vcpus) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                        _("Could not set number of virtual cpu"));
            goto exit;
        }
    }

 exit:
    cmdExecFree(progcreate);
    return dom;
}

static int
openvzDomainCreate(virDomainPtr dom)
{
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByName(driver->domains, dom->name);
    const char *prog[] = {VZCTL, "--quiet", "start", vm ? vm->def->name : NULL, NULL };

    if (!vm) {
        openvzError(dom->conn, VIR_ERR_INVALID_DOMAIN,
              _("no domain with matching id"));
        return -1;
    }

    if (vm->state != VIR_DOMAIN_SHUTOFF) {
        openvzError(dom->conn, VIR_ERR_OPERATION_DENIED,
              _("domain is not in shutoff state"));
        return -1;
    }

    if (virRun(dom->conn, prog, NULL) < 0) {
        openvzError(dom->conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZCTL);
        return -1;
    }

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;

    return 0;
}

static int
openvzDomainUndefine(virDomainPtr dom)
{
    virConnectPtr conn= dom->conn;
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    const char *prog[] = { VZCTL, "--quiet", "destroy", vm ? vm->def->name : NULL, NULL };

    if (!vm) {
        openvzError(conn, VIR_ERR_INVALID_DOMAIN, _("no domain with matching uuid"));
        return -1;
    }

    if (virDomainIsActive(vm)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("cannot delete active domain"));
        return -1;
    }

    if (virRun(conn, prog, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
               _("Could not exec %s"), VZCTL);
        return -1;
    }

    virDomainRemoveInactive(&driver->domains, vm);

    return 0;
}

static int
openvzDomainSetAutostart(virDomainPtr dom, int autostart)
{
    virConnectPtr conn= dom->conn;
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    const char *prog[] = { VZCTL, "--quiet", "set", vm ? vm->def->name : NULL,
                           "--onboot", autostart ? "yes" : "no",
                           "--save", NULL };

    if (!vm) {
        openvzError(conn, VIR_ERR_INVALID_DOMAIN, _("no domain with matching uuid"));
        return -1;
    }

    if (virRun(conn, prog, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("Could not exec %s"), VZCTL);
        return -1;
    }

    return 0;
}

static int
openvzDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    virConnectPtr conn= dom->conn;
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    char value[1024];

    if (!vm) {
        openvzError(conn, VIR_ERR_INVALID_DOMAIN, _("no domain with matching uuid"));
        return -1;
    }

    if (openvzReadConfigParam(strtoI(vm->def->name), "ONBOOT", value, sizeof(value)) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("Could not read container config"));
        return -1;
    }

    *autostart = 0;
    if (STREQ(value,"yes"))
        *autostart = 1;

    return 0;
}

static int openvzGetMaxVCPUs(virConnectPtr conn, const char *type) {
    if (STRCASEEQ(type, "openvz"))
        return 1028; //OpenVZ has no limitation

    openvzError(conn, VIR_ERR_INVALID_ARG,
                     _("unknown type '%s'"), type);
    return -1;
}


static int openvzDomainGetMaxVcpus(virDomainPtr dom) {
    return openvzGetMaxVCPUs(dom->conn, "openvz");
}

static int openvzDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus) {
    virConnectPtr conn= dom->conn;
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    char   str_vcpus[32];
    const char *prog[] = { VZCTL, "--quiet", "set", vm ? vm->def->name : NULL,
                           "--cpus", str_vcpus, "--save", NULL };


    if (!vm) {
        openvzError(conn, VIR_ERR_INVALID_DOMAIN,
                    _("no domain with matching uuid"));
        return -1;
    }

    if (nvcpus <= 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    _("VCPUs should be >= 1"));
        return -1;
    }

    snprintf(str_vcpus, 31, "%d", nvcpus);
    str_vcpus[31] = '\0';

    if (virRun(conn, prog, NULL) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    _("Could not exec %s"), VZCTL);
        return -1;
    }

    vm->def->vcpus = nvcpus;
    return 0;
}

static const char *openvzProbe(void)
{
#ifdef __linux__
    if ((geteuid() == 0) && (virFileExists("/proc/vz")))
        return("openvz:///system");
#endif
    return(NULL);
}

static virDrvOpenStatus openvzOpen(virConnectPtr conn,
                                 xmlURIPtr uri,
                                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                 int flags ATTRIBUTE_UNUSED)
{
    struct openvz_driver *driver;
    /*Just check if the user is root. Nothing really to open for OpenVZ */
    if (geteuid()) { // OpenVZ tools can only be used by r00t
        return VIR_DRV_OPEN_DECLINED;
    } else {
        if (uri == NULL ||
            uri->scheme == NULL ||
            uri->path == NULL ||
            STRNEQ (uri->scheme, "openvz") ||
            STRNEQ (uri->path, "/system"))
            return VIR_DRV_OPEN_DECLINED;
    }
    /* See if we are running an OpenVZ enabled kernel */
    if(access("/proc/vz/veinfo", F_OK) == -1 ||
       access("/proc/user_beancounters", F_OK) == -1) {
        return VIR_DRV_OPEN_DECLINED;
    }

    if (VIR_ALLOC(driver) < 0) {
        openvzError(conn, VIR_ERR_NO_MEMORY, NULL);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!(driver->caps = openvzCapsInit()))
        goto cleanup;

    if (openvzLoadDomains(driver) < 0)
        goto cleanup;

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

cleanup:
    openvzFreeDriver(driver);
    return VIR_DRV_OPEN_ERROR;
};

static int openvzClose(virConnectPtr conn) {
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;

    openvzFreeDriver(driver);
    conn->privateData = NULL;

    return 0;
}

static const char *openvzGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return strdup("OpenVZ");
}

static int openvzGetNodeInfo(virConnectPtr conn,
                             virNodeInfoPtr nodeinfo) {
    return virNodeInfoPopulate(conn, nodeinfo);
}

static char *openvzGetCapabilities(virConnectPtr conn) {
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;

    return virCapabilitiesFormatXML(driver->caps);
}

static int openvzListDomains(virConnectPtr conn, int *ids, int nids) {
    int got = 0;
    int veid, pid;
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

static int openvzNumDomains(virConnectPtr conn ATTRIBUTE_UNUSED) {
    struct openvz_driver *driver = conn->privateData;
    int nactive = 0;
    virDomainObjPtr vm = driver->domains;
    while (vm) {
        if (virDomainIsActive(vm))
            nactive++;
        vm = vm->next;
    }
    return nactive;
}

static int openvzListDefinedDomains(virConnectPtr conn,
                                    char **const names, int nnames) {
    int got = 0;
    int veid, pid, outfd = -1, errfd = -1, ret;
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
    openvzError(conn, VIR_ERR_NO_MEMORY, NULL);
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
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    int ninactive = 0;
    virDomainObjPtr vm = driver->domains;
    while (vm) {
        if (!virDomainIsActive(vm))
            ninactive++;
        vm = vm->next;
    }
    return ninactive;
}

static virDriver openvzDriver = {
    VIR_DRV_OPENVZ,
    "OPENVZ",
    LIBVIR_VERSION_NUMBER,
    openvzProbe, /* probe */
    openvzOpen, /* open */
    openvzClose, /* close */
    NULL, /* supports_feature */
    openvzGetType, /* type */
    NULL, /* version */
    NULL, /* hostname */
    NULL, /* uri */
    openvzGetMaxVCPUs, /* getMaxVcpus */
    openvzGetNodeInfo, /* nodeGetInfo */
    openvzGetCapabilities, /* getCapabilities */
    openvzListDomains, /* listDomains */
    openvzNumDomains, /* numOfDomains */
    openvzDomainCreateLinux, /* domainCreateLinux */
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
    openvzDomainDumpXML, /* domainDumpXML */
    openvzListDefinedDomains, /* listDomains */
    openvzNumDefinedDomains, /* numOfDomains */
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
    NULL, /* nodeGetFreeMemory */
};

int openvzRegister(void) {
    virRegisterDriver(&openvzDriver);
    return 0;
}

