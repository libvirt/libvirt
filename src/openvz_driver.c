/*
 * openvz_driver.c: core driver methods for managing OpenVZ VEs
 *
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
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
 * Author: Shuveb Hussain <shuveb@binarykarma.com>
 */

#ifdef WITH_OPENVZ

#include <config.h>

#define _GNU_SOURCE /* for asprintf */

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
#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>

#include <libvirt/virterror.h>

#include "event.h"
#include "buf.h"
#include "util.h"
#include "openvz_driver.h"
#include "openvz_conf.h"
#include "nodeinfo.h"


#define openvzLog(level, msg...) fprintf(stderr, msg)

static virDomainPtr openvzDomainLookupByID(virConnectPtr conn, int id);
static char *openvzGetOSType(virDomainPtr dom);
static int openvzGetNodeInfo(virConnectPtr conn, virNodeInfoPtr nodeinfo);
static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid);
static virDomainPtr openvzDomainLookupByName(virConnectPtr conn, const char *name);
static int openvzDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info);
static int openvzDomainShutdown(virDomainPtr dom);
static int openvzDomainReboot(virDomainPtr dom, unsigned int flags);
static int openvzDomainCreate(virDomainPtr dom);
static virDrvOpenStatus openvzOpen(virConnectPtr conn, const char *name,
                           int flags ATTRIBUTE_UNUSED);
static int openvzClose(virConnectPtr conn);
static const char *openvzGetType(virConnectPtr conn ATTRIBUTE_UNUSED);
static int openvzListDomains(virConnectPtr conn, int *ids, int nids);
static int openvzNumDomains(virConnectPtr conn);
static int openvzListDefinedDomains(virConnectPtr conn, char **const names, int nnames);
static int openvzNumDefinedDomains(virConnectPtr conn);
static int openvzStartup(void);
static int openvzShutdown(void);
static int openvzReload(void);
static int openvzActive(void);
static int openvzCloseNetwork(virConnectPtr conn);
static virDrvOpenStatus openvzOpenNetwork(virConnectPtr conn, const char *name ATTRIBUTE_UNUSED,
                                         int flags ATTRIBUTE_UNUSED);
struct openvz_driver ovz_driver;

/* For errors internal to this library. */
static void
error (virConnectPtr conn, virErrorNumber code, const char *info)
{
    const char *errmsg;

    errmsg = __virErrorMsg (code, info);
    __virRaiseError (conn, NULL, NULL, VIR_FROM_REMOTE,
                     code, VIR_ERR_ERROR, errmsg, info, NULL, 0, 0,
                     errmsg, info);
}

static virDomainPtr openvzDomainLookupByID(virConnectPtr conn,
                                   int id) {
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    struct openvz_vm *vm = openvzFindVMByID(driver, id);
    virDomainPtr dom;

    if (!vm) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "no domain with matching id");
        return NULL;
    }

    dom = virGetDomain(conn, vm->vmdef->name, vm->vmdef->uuid);
    if (!dom) {
        error(conn, VIR_ERR_NO_MEMORY, "virDomainPtr");
        return NULL;
    }

    dom->id = vm->vpsid;
    return dom;
}

static char *openvzGetOSType(virDomainPtr dom)
{
    /* OpenVZ runs on Linux and runs only Linux */
    return strdup("Linux");
}


static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn,
                                     const unsigned char *uuid) {
    struct  openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    struct openvz_vm *vm = openvzFindVMByUUID(driver, uuid);
    virDomainPtr dom;

    if (!vm) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "no domain with matching uuid");
        return NULL;
    }

    dom = virGetDomain(conn, vm->vmdef->name, vm->vmdef->uuid);
    if (!dom) {
        error(conn, VIR_ERR_NO_MEMORY, "virDomainPtr");
        return NULL;
    }

    dom->id = vm->vpsid;
    return dom;
}

static virDomainPtr openvzDomainLookupByName(virConnectPtr conn,
                                     const char *name) {
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    struct openvz_vm *vm = openvzFindVMByName(driver, name);
    virDomainPtr dom;

    if (!vm) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "no domain with matching name");
        return NULL;
    }

    dom = virGetDomain(conn, vm->vmdef->name, vm->vmdef->uuid);
    if (!dom) {
        error(conn, VIR_ERR_NO_MEMORY, "virDomainPtr");
        return NULL;
    }

    dom->id = vm->vpsid;
    return dom;
}

static int openvzDomainGetInfo(virDomainPtr dom,
                       virDomainInfoPtr info) {
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    struct openvz_vm *vm = openvzFindVMByUUID(driver, dom->uuid);
    if (!vm) {
        error(dom->conn, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    info->state = vm->status;

    /* TODO These need to be calculated differently for OpenVZ */
    //info->cpuTime = 
    //info->maxMem = vm->def->maxmem;
    //info->memory = vm->def->memory;
    //info->nrVirtCpu = vm->def->vcpus;
    return 0;
}

static int openvzDomainShutdown(virDomainPtr dom) {
    char cmdbuf[1024];
    int ret;
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    struct openvz_vm *vm = openvzFindVMByID(driver, dom->id);

    if (!vm) {
        error(dom->conn, VIR_ERR_INVALID_DOMAIN, "no domain with matching id");
        return -1;
    }
    
    if (vm->status != VIR_DOMAIN_RUNNING) {
        error(dom->conn, VIR_ERR_OPERATION_DENIED, "domain is not in running state");
        return -1;
    }

    snprintf(cmdbuf, 1024, VZCTL " stop %d >/dev/null 2>&1", dom->id);
    ret = system(cmdbuf);
    if(WEXITSTATUS(ret)) {
        error(dom->conn, VIR_ERR_OPERATION_FAILED, "could not shutdown domain");
        return -1;
    }
    vm->vpsid = -1;
    vm->status = VIR_DOMAIN_SHUTOFF;
    ovz_driver.num_inactive ++;
    ovz_driver.num_active --;
    
    return ret;
}

static int openvzDomainReboot(virDomainPtr dom, unsigned int flags) {
    char cmdbuf[1024];
    int ret;
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    struct openvz_vm *vm = openvzFindVMByID(driver, dom->id);

    if (!vm) {
        error(dom->conn, VIR_ERR_INVALID_DOMAIN, "no domain with matching id");
        return -1;
    }
    
    if (vm->status != VIR_DOMAIN_RUNNING) {
        error(dom->conn, VIR_ERR_OPERATION_DENIED, "domain is not in running state");
        return -1;
    }

    snprintf(cmdbuf, 1024, VZCTL " restart %d >/dev/null 2>&1", dom->id);
    ret = system(cmdbuf);
    if(WEXITSTATUS(ret)) {
        error(dom->conn, VIR_ERR_OPERATION_FAILED, "could not reboot domain");
        return -1;
    }
    
    return ret;
}

static int openvzDomainCreate(virDomainPtr dom) {
    char cmdbuf[1024];
    int ret;
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    struct openvz_vm *vm = openvzFindVMByID(driver, dom->id);
    struct openvz_vm_def *vmdef;

    if (!vm) {
        error(dom->conn, VIR_ERR_INVALID_DOMAIN, "no domain with matching id");
        return -1;
    }
    
    if (vm->status != VIR_DOMAIN_SHUTOFF) {
        error(dom->conn, VIR_ERR_OPERATION_DENIED, "domain is not in shutoff state");
        return -1;
    }

    vmdef = vm->vmdef;
    snprintf(cmdbuf, 1024, VZCTL " start %s >/dev/null 2>&1", vmdef->name);
    ret = system(cmdbuf);
    if(WEXITSTATUS(ret)) {
        error(dom->conn, VIR_ERR_OPERATION_FAILED, "could not start domain");
        return -1;
    }
    sscanf(vmdef->name, "%d", &vm->vpsid); 
    vm->status = VIR_DOMAIN_RUNNING;
    ovz_driver.num_inactive --;
    ovz_driver.num_active ++;

    return ret;
}

static virDrvOpenStatus openvzOpen(virConnectPtr conn,
                           const char *name,
                           int flags ATTRIBUTE_UNUSED) {
    struct openvz_vm *vms;

    /* Just check if the guy is root. Nothing really to open for OpenVZ */
    if (getuid()) { // OpenVZ tools can only be used by r00t
            return VIR_DRV_OPEN_DECLINED;
    } else {
        if (strcmp(name, "openvz:///system")) 
            return VIR_DRV_OPEN_DECLINED;
    }
    /* See if we are running an OpenVZ enabled kernel */
    if(access("/proc/vz/veinfo", F_OK) == -1 || 
                access("/proc/user_beancounters", F_OK) == -1) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->privateData = &ovz_driver;

    virStateInitialize();
    vms = openvzGetVPSInfo(conn);
    ovz_driver.vms = vms;

    return VIR_DRV_OPEN_SUCCESS;
}

static int openvzClose(virConnectPtr conn) {
    
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    struct openvz_vm *vm = driver->vms;
    

    while(vm) {
        openvzFreeVMDef(vm->vmdef);
        vm = vm->next;
    }
    vm = driver->vms;
    while (vm) {
        struct openvz_vm *prev = vm;
        vm = vm->next;
        free(prev);
    }
    
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


static int openvzListDomains(virConnectPtr conn, int *ids, int nids) {
    int got = 0;
    int veid, pid, outfd, errfd;
    int ret;
    char buf[32];
    const char *cmd[] = {VZLIST, "-ovpsid", "-H" , NULL};

    ret = virExec(conn, (char **)cmd, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return (int)NULL;
    }

    while(got < nids){
        ret = openvz_readline(outfd, buf, 32);
        if(!ret) break;
        sscanf(buf, "%d", &veid);
        ids[got] = veid;
        got ++;
    }
    waitpid(pid, NULL, 0);

    return got;
}

static int openvzNumDomains(virConnectPtr conn) {
    return ovz_driver.num_active;
}

static int openvzListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    int got = 0;
    int veid, pid, outfd, errfd, ret;
    char vpsname[OPENVZ_NAME_MAX];
    char buf[32];
    const char *cmd[] = {VZLIST, "-ovpsid", "-H", NULL};

    /* the -S options lists only stopped domains */
    ret = virExec(conn, (char **)cmd, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return (int)NULL;
    }

    while(got < nnames){
        ret = openvz_readline(outfd, buf, 32);
        if(!ret) break;
        sscanf(buf, "%d\n", &veid);
        sprintf(vpsname, "%d", veid);
        names[got] = strdup(vpsname);
        got ++;
    }
    waitpid(pid, NULL, 0);
    return got;
}


static int openvzNumDefinedDomains(virConnectPtr conn) {
    return ovz_driver.num_inactive; 
}

static int openvzStartup(void) {
    openvzAssignUUIDs();
    
    return 0;
}

static int openvzShutdown(void) {

    return 0;
}

static int openvzReload(void) {

    return 0;
}

static int openvzActive(void) {

    return 1;
}

static int openvzCloseNetwork(virConnectPtr conn) {
    return 0;
}

static virDrvOpenStatus openvzOpenNetwork(virConnectPtr conn,
                                         const char *name ATTRIBUTE_UNUSED,
                                         int flags ATTRIBUTE_UNUSED) {
    return VIR_DRV_OPEN_SUCCESS;
}


static virDriver openvzDriver = {
    VIR_DRV_OPENVZ,
    "OPENVZ",
    LIBVIR_VERSION_NUMBER,
    openvzOpen, /* open */
    openvzClose, /* close */
    openvzGetType, /* type */
    NULL, /* version */
    NULL, /* hostname */
    NULL, /* uri */
    NULL, /* getMaxVcpus */
    openvzGetNodeInfo, /* nodeGetInfo */
    NULL, /* getCapabilities */
    openvzListDomains, /* listDomains */
    openvzNumDomains, /* numOfDomains */
    NULL, /* domainCreateLinux */
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
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    NULL, /* domainDumpXML */
    openvzListDefinedDomains, /* listDomains */
    openvzNumDefinedDomains, /* numOfDomains */
    openvzDomainCreate, /* domainCreate */
    NULL, /* domainDefineXML */
    NULL, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
};

static virNetworkDriver openvzNetworkDriver = {
    openvzOpenNetwork, /* open */
    openvzCloseNetwork, /* close */
    NULL, /* numOfNetworks */
    NULL, /* listNetworks */
    NULL, /* numOfDefinedNetworks */
    NULL, /* listDefinedNetworks */
    NULL, /* networkLookupByUUID */
    NULL, /* networkLookupByName */
    NULL, /* networkCreateXML */
    NULL, /* networkDefineXML */
    NULL, /* networkUndefine */
    NULL, /* networkCreate */
    NULL, /* networkDestroy */
    NULL, /* networkDumpXML */
    NULL, /* networkGetBridgeName */
    NULL, /* networkGetAutostart */
    NULL, /* networkSetAutostart */
};

static virStateDriver openvzStateDriver = {
    openvzStartup,
    openvzShutdown,
    openvzReload,
    openvzActive,
};

int openvzRegister(void) {
    virRegisterDriver(&openvzDriver);
    virRegisterNetworkDriver(&openvzNetworkDriver);
    virRegisterStateDriver(&openvzStateDriver);
    return 0;
}

#endif /* WITH_OPENVZ */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
