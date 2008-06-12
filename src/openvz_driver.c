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

#ifdef WITH_OPENVZ

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

#define OPENVZ_MAX_ARG 28
#define CMDBUF_LEN 1488
#define CMDOP_LEN 288

static virDomainPtr openvzDomainLookupByID(virConnectPtr conn, int id);
static char *openvzGetOSType(virDomainPtr dom);
static int openvzGetNodeInfo(virConnectPtr conn, virNodeInfoPtr nodeinfo);
static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid);
static virDomainPtr openvzDomainLookupByName(virConnectPtr conn, const char *name);
static int openvzDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info);
static int openvzDomainShutdown(virDomainPtr dom);
static int openvzDomainReboot(virDomainPtr dom, unsigned int flags);
static int openvzDomainCreate(virDomainPtr dom);
static virDrvOpenStatus openvzOpen(virConnectPtr conn,
                                 xmlURIPtr uri,
                                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
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

static virDomainPtr openvzDomainDefineXML(virConnectPtr conn, const char *xml);
static virDomainPtr openvzDomainCreateLinux(virConnectPtr conn, const char *xml,
        unsigned int flags ATTRIBUTE_UNUSED);

static int openvzDomainUndefine(virDomainPtr dom);
static int convCmdbufExec(char cmdbuf[], char *cmdExec[]);
static void cmdExecFree(char *cmdExec[]);

struct openvz_driver ovz_driver;

static int convCmdbufExec(char cmdbuf[], char *cmdExec[])
{
    int i=0, limit = OPENVZ_MAX_ARG - 1;
    char cmdWord[CMDOP_LEN];
    while(*cmdbuf)
    {
        if(i >= limit)
        {
            cmdExec[i] = NULL;
            return -1;
        }
        sscanf(cmdbuf, "%s", cmdWord);
        cmdbuf += strlen(cmdWord);
        while(*cmdbuf == ' ') cmdbuf++;
        cmdExec[i++] = strdup(cmdWord);
    }
    cmdExec[i] = NULL;
    return i;
}

static void cmdExecFree(char *cmdExec[])
{
    int i=-1;
    while(cmdExec[++i])
    {
        free(cmdExec[i]);
        cmdExec[i] = NULL;
    }
}

/* For errors internal to this library. */
static void
error (virConnectPtr conn, virErrorNumber code, const char *info)
{
    const char *errmsg;

    errmsg = __virErrorMsg (code, info);
    __virRaiseError (conn, NULL, NULL, VIR_FROM_OPENVZ,
                     code, VIR_ERR_ERROR, errmsg, info, NULL, 0, 0,
                     errmsg, info);
}

static virDomainPtr openvzDomainLookupByID(virConnectPtr conn,
                                   int id) {
    struct openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    struct openvz_vm *vm = openvzFindVMByID(driver, id);
    virDomainPtr dom;

    if (!vm) {
        error(conn, VIR_ERR_INTERNAL_ERROR, _("no domain with matching id"));
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

static char *openvzGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    /* OpenVZ runs on Linux and runs only Linux */
    return strdup("linux");
}


static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn,
                                     const unsigned char *uuid) {
    struct  openvz_driver *driver = (struct openvz_driver *)conn->privateData;
    struct openvz_vm *vm = openvzFindVMByUUID(driver, uuid);
    virDomainPtr dom;

    if (!vm) {
        error(conn, VIR_ERR_INVALID_DOMAIN, _("no domain with matching uuid"));
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
        error(conn, VIR_ERR_INTERNAL_ERROR, _("no domain with matching name"));
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
        error(dom->conn, VIR_ERR_INVALID_DOMAIN,
              _("no domain with matching uuid"));
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
    char cmdbuf[CMDBUF_LEN];
    int ret;
    char *cmdExec[OPENVZ_MAX_ARG];
    int pid, outfd, errfd;
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    struct openvz_vm *vm = openvzFindVMByID(driver, dom->id);

    if (!vm) {
        error(dom->conn, VIR_ERR_INVALID_DOMAIN,
              _("no domain with matching id"));
        return -1;
    }

    if (vm->status != VIR_DOMAIN_RUNNING) {
        error(dom->conn, VIR_ERR_OPERATION_DENIED,
              _("domain is not in running state"));
        return -1;
    }
    snprintf(cmdbuf, CMDBUF_LEN - 1, VZCTL " stop %d ", dom->id);

    if((ret = convCmdbufExec(cmdbuf, cmdExec)) == -1)
    {
        openvzLog(OPENVZ_ERR, "%s", _("Error in parsing Options to OPENVZ"));
        goto bail_out;
    }

    ret = virExec(dom->conn, (char **)cmdExec, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(dom->conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return -1;
    }

    vm->vpsid = -1;
    vm->status = VIR_DOMAIN_SHUTOFF;
    ovz_driver.num_inactive ++;
    ovz_driver.num_active --;

bail_out:
    cmdExecFree(cmdExec);

    return ret;
}

static int openvzDomainReboot(virDomainPtr dom,
                              unsigned int flags ATTRIBUTE_UNUSED) {
    char cmdbuf[CMDBUF_LEN];
    int ret;
    char *cmdExec[OPENVZ_MAX_ARG];
    int pid, outfd, errfd;
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    struct openvz_vm *vm = openvzFindVMByID(driver, dom->id);

    if (!vm) {
        error(dom->conn, VIR_ERR_INVALID_DOMAIN,
              _("no domain with matching id"));
        return -1;
    }

    if (vm->status != VIR_DOMAIN_RUNNING) {
        error(dom->conn, VIR_ERR_OPERATION_DENIED,
              _("domain is not in running state"));
        return -1;
    }
    snprintf(cmdbuf, CMDBUF_LEN - 1, VZCTL " restart %d ", dom->id);

    if((ret = convCmdbufExec(cmdbuf, cmdExec)) == -1)
    {
        openvzLog(OPENVZ_ERR, "%s", _("Error in parsing Options to OPENVZ"));
        goto bail_out1;
    }
    ret = virExec(dom->conn, (char **)cmdExec, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(dom->conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return -1;
    }

bail_out1:
    cmdExecFree(cmdExec);

    return ret;
}

static virDomainPtr
openvzDomainDefineXML(virConnectPtr conn, const char *xml)
{
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    struct openvz_vm_def *vmdef = NULL;
    struct openvz_vm *vm = NULL;
    virDomainPtr dom;
    char cmdbuf[CMDBUF_LEN], cmdOption[CMDOP_LEN], *cmdExec[OPENVZ_MAX_ARG];
    int ret, pid, outfd, errfd;

    if (!(vmdef = openvzParseVMDef(conn, xml, NULL)))
        goto bail_out2;

    vm = openvzFindVMByID(driver, strtoI(vmdef->name));
    if (vm) {
        openvzLog(OPENVZ_ERR, _("Already an OPENVZ VM active with the id '%s'"),
                  vmdef->name);
        goto bail_out2;
    }
    if (!(vm = openvzAssignVMDef(conn, driver, vmdef))) {
        openvzFreeVMDef(vmdef);
        openvzLog(OPENVZ_ERR, "%s", _("Error creating OPENVZ VM"));
    }

    snprintf(cmdbuf, CMDBUF_LEN - 1, VZCTL " create %s", vmdef->name);
    if ((vmdef->fs.tmpl && *(vmdef->fs.tmpl))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --ostemplate %s", vmdef->fs.tmpl);
        strcat(cmdbuf, cmdOption);
    }
    if ((vmdef->profile && *(vmdef->profile))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --config %s", vmdef->profile);
        strcat(cmdbuf, cmdOption);
    }
    if ((vmdef->net.ips->ip && *(vmdef->net.ips->ip))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --ipadd %s", vmdef->net.ips->ip);
        strcat(cmdbuf, cmdOption);
    }
    if ((vmdef->net.hostname && *(vmdef->net.hostname))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --hostname %s", vmdef->net.hostname);
        strcat(cmdbuf, cmdOption);
    }

    if((ret = convCmdbufExec(cmdbuf, cmdExec)) == -1)
    {
        openvzLog(OPENVZ_ERR, "%s", _("Error in parsing Options to OPENVZ"));
        goto bail_out2;
    }
    ret = virExec(conn, (char **)cmdExec, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        goto bail_out2;
    }

    waitpid(pid, NULL, 0);
    cmdExecFree(cmdExec);

    dom = virGetDomain(conn, vm->vmdef->name, vm->vmdef->uuid);
    if (dom)
        dom->id = vm->vpsid;
    return dom;
bail_out2:
    cmdExecFree(cmdExec);
    return NULL;
}

static virDomainPtr
openvzDomainCreateLinux(virConnectPtr conn, const char *xml,
                        unsigned int flags ATTRIBUTE_UNUSED)
{
    struct openvz_vm_def *vmdef = NULL;
    struct openvz_vm *vm = NULL;
    virDomainPtr dom;
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    char cmdbuf[CMDBUF_LEN], cmdOption[CMDOP_LEN], *cmdExec[OPENVZ_MAX_ARG];
    int ret, pid, outfd, errfd;

    if (!(vmdef = openvzParseVMDef(conn, xml, NULL)))
        return NULL;

    vm = openvzFindVMByID(driver, strtoI(vmdef->name));
    if (vm) {
        openvzFreeVMDef(vmdef);
        openvzLog(OPENVZ_ERR,
                  _("Already an OPENVZ VM defined with the id '%d'"),
                strtoI(vmdef->name));
        return NULL;
    }
    if (!(vm = openvzAssignVMDef(conn, driver, vmdef))) {
        openvzLog(OPENVZ_ERR, "%s", _("Error creating OPENVZ VM"));
        return NULL;
    }

    snprintf(cmdbuf, CMDBUF_LEN - 1, VZCTL " create %s", vmdef->name);
    if ((vmdef->fs.tmpl && *(vmdef->fs.tmpl))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --ostemplate %s", vmdef->fs.tmpl);
        strcat(cmdbuf, cmdOption);
    }
    if ((vmdef->profile && *(vmdef->profile))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --config %s", vmdef->profile);
        strcat(cmdbuf, cmdOption);
    }
    if ((vmdef->net.ips->ip && *(vmdef->net.ips->ip))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --ipadd %s", vmdef->net.ips->ip);
        strcat(cmdbuf, cmdOption);
    }
    if ((vmdef->net.hostname && *(vmdef->net.hostname))) {
        snprintf(cmdOption, CMDOP_LEN - 1, " --hostname %s", vmdef->net.hostname);
        strcat(cmdbuf, cmdOption);
    }

    if((ret = convCmdbufExec(cmdbuf, cmdExec)) == -1)
    {
        openvzLog(OPENVZ_ERR, "%s", _("Error in parsing Options to OPENVZ"));
        goto bail_out3;
    }
    ret = virExec(conn, (char **)cmdExec, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return NULL;
    }

    waitpid(pid, NULL, 0);
    cmdExecFree(cmdExec);

    snprintf(cmdbuf, CMDBUF_LEN - 1, VZCTL " start %s ", vmdef->name);

    if((ret = convCmdbufExec(cmdbuf, cmdExec)) == -1)
    {
        openvzLog(OPENVZ_ERR, "%s", _("Error in parsing Options to OPENVZ"));
        goto bail_out3;
    }
    ret = virExec(conn, (char **)cmdExec, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return NULL;
    }

    sscanf(vmdef->name, "%d", &vm->vpsid);
    vm->status = VIR_DOMAIN_RUNNING;
    ovz_driver.num_inactive--;
    ovz_driver.num_active++;

    waitpid(pid, NULL, 0);
    cmdExecFree(cmdExec);

    dom = virGetDomain(conn, vm->vmdef->name, vm->vmdef->uuid);
    if (dom)
        dom->id = vm->vpsid;
    return dom;
bail_out3:
    cmdExecFree(cmdExec);
    return NULL;
}

static int
openvzDomainCreate(virDomainPtr dom)
{
    char cmdbuf[CMDBUF_LEN];
    int ret;
    char *cmdExec[OPENVZ_MAX_ARG] ;
    int pid, outfd, errfd;
    struct openvz_driver *driver = (struct openvz_driver *)dom->conn->privateData;
    struct openvz_vm *vm = openvzFindVMByName(driver, dom->name);
    struct openvz_vm_def *vmdef;

    if (!vm) {
        error(dom->conn, VIR_ERR_INVALID_DOMAIN,
              _("no domain with matching id"));
        return -1;
    }

    if (vm->status != VIR_DOMAIN_SHUTOFF) {
        error(dom->conn, VIR_ERR_OPERATION_DENIED,
              _("domain is not in shutoff state"));
        return -1;
    }

    vmdef = vm->vmdef;
    snprintf(cmdbuf, CMDBUF_LEN - 1, VZCTL " start %s ", vmdef->name);

    if((ret = convCmdbufExec(cmdbuf, cmdExec)) == -1)
    {
        openvzLog(OPENVZ_ERR, "%s", _("Error in parsing Options to OPENVZ"));
        goto bail_out4;
    }
    ret = virExec(dom->conn, (char **)cmdExec, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(dom->conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return -1;
    }

    sscanf(vmdef->name, "%d", &vm->vpsid);
    vm->status = VIR_DOMAIN_RUNNING;
    ovz_driver.num_inactive --;
    ovz_driver.num_active ++;

    waitpid(pid, NULL, 0);
bail_out4:
    cmdExecFree(cmdExec);

    return ret;
}

static int
openvzDomainUndefine(virDomainPtr dom)
{
    char cmdbuf[CMDBUF_LEN], *cmdExec[OPENVZ_MAX_ARG];
    int ret, pid, outfd, errfd;
    virConnectPtr conn= dom->conn;
    struct openvz_driver *driver = (struct openvz_driver *) conn->privateData;
    struct openvz_vm *vm = openvzFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        error(conn, VIR_ERR_INVALID_DOMAIN, _("no domain with matching uuid"));
        return -1;
    }

    if (openvzIsActiveVM(vm)) {
        error(conn, VIR_ERR_INTERNAL_ERROR, _("cannot delete active domain"));
        return -1;
    }
    snprintf(cmdbuf, CMDBUF_LEN - 1, VZCTL " destroy %s ", vm->vmdef->name);

    if((ret = convCmdbufExec(cmdbuf, cmdExec)) == -1)
    {
        openvzLog(OPENVZ_ERR, "%s", _("Error in parsing Options to OPENVZ"));
        goto bail_out5;
    }
    ret = virExec(conn, (char **)cmdExec, &pid, -1, &outfd, &errfd);
    if(ret == -1) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "Could not exec " VZLIST);
        return -1;
    }

    waitpid(pid, NULL, 0);
    openvzRemoveInactiveVM(driver, vm);
bail_out5:
    cmdExecFree(cmdExec);
    return ret;
}

static const char *openvzProbe(void)
{
#ifdef __linux__
    if ((getuid() == 0) && (virFileExists("/proc/vz")))
        return("openvz:///");
#endif
    return(NULL);
}

static virDrvOpenStatus openvzOpen(virConnectPtr conn,
                                 xmlURIPtr uri,
                                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                 int flags ATTRIBUTE_UNUSED)
{
   struct openvz_vm *vms;

    /*Just check if the user is root. Nothing really to open for OpenVZ */
   if (getuid()) { // OpenVZ tools can only be used by r00t
           return VIR_DRV_OPEN_DECLINED;
   } else {
       if (uri == NULL || uri->scheme == NULL || uri->path == NULL)
                   return VIR_DRV_OPEN_DECLINED;
       if (STRNEQ (uri->scheme, "openvz"))
                   return VIR_DRV_OPEN_DECLINED;
       if (STRNEQ (uri->path, "/system"))
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
};

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

static int openvzNumDomains(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return ovz_driver.num_active;
}

static int openvzListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    int got = 0;
    int veid, pid, outfd, errfd, ret;
    char vpsname[OPENVZ_NAME_MAX];
    char buf[32];
    const char *cmd[] = {VZLIST, "-ovpsid", "-H", "-S", NULL};

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

static int openvzNumDefinedDomains(virConnectPtr conn ATTRIBUTE_UNUSED) {
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
    NULL, /* getMaxVcpus */
    openvzGetNodeInfo, /* nodeGetInfo */
    NULL, /* getCapabilities */
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
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    NULL, /* domainDumpXML */
    openvzListDefinedDomains, /* listDomains */
    openvzNumDefinedDomains, /* numOfDomains */
    openvzDomainCreate, /* domainCreate */
    openvzDomainDefineXML, /* domainDefineXML */
    openvzDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
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

static virStateDriver openvzStateDriver = {
    openvzStartup,
    openvzShutdown,
    openvzReload,
    openvzActive,
    NULL, /* sigHandler */
};

int openvzRegister(void) {
    virRegisterDriver(&openvzDriver);
    virRegisterStateDriver(&openvzStateDriver);
    return 0;
}

#endif /* WITH_OPENVZ */
