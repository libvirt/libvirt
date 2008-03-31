/*
 * Copyright IBM Corp. 2008
 *
 * lxc_driver.c: linux container driver functions
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <config.h>

#ifdef WITH_LXC

#include <sched.h>
#include <sys/utsname.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>

#include "lxc_conf.h"
#include "lxc_driver.h"
#include "driver.h"
#include "internal.h"

/* debug macros */
#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

/*
 * GLibc headers are behind the kernel, so we define these
 * constants if they're not present already.
 */

#ifndef CLONE_NEWPID
#define CLONE_NEWPID  0x20000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS  0x04000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC  0x08000000
#endif

static int lxcStartup(void);
static int lxcShutdown(void);
static lxc_driver_t *lxc_driver = NULL;

/* Functions */
static int lxcDummyChild( void *argv ATTRIBUTE_UNUSED )
{
    exit(0);
}

static int lxcCheckContainerSupport( void )
{
    int rc = 0;
    int flags = CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWUSER|
        CLONE_NEWIPC|SIGCHLD;
    int cpid;
    char *childStack;
    char *stack;
    int childStatus;

    stack = malloc(getpagesize() * 4);
    if(!stack) {
        DEBUG0("Unable to allocate stack");
        rc = -1;
        goto check_complete;
    }

    childStack = stack + (getpagesize() * 4);

    cpid = clone(lxcDummyChild, childStack, flags, NULL);
    if ((0 > cpid) && (EINVAL == errno)) {
        DEBUG0("clone call returned EINVAL, container support is not enabled");
        rc = -1;
    } else {
        waitpid(cpid, &childStatus, 0);
    }

    free(stack);

check_complete:
    return rc;
}

static const char *lxcProbe(void)
{
#ifdef __linux__
    if (0 == lxcCheckContainerSupport()) {
        return("lxc:///");
    }
#endif
    return(NULL);
}

static virDrvOpenStatus lxcOpen(virConnectPtr conn,
                                xmlURIPtr uri,
                                virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                int flags ATTRIBUTE_UNUSED)
{
    uid_t uid = getuid();

    /* Check that the user is root */
    if (0 != uid) {
        goto declineConnection;
    }

    if (lxc_driver == NULL)
        goto declineConnection;

    /* Verify uri was specified */
    if ((NULL == uri) || (NULL == uri->scheme)) {
        goto declineConnection;
    }

    /* Check that the uri scheme is lxc */
    if (STRNEQ(uri->scheme, "lxc")) {
        goto declineConnection;
    }

    conn->privateData = lxc_driver;

    return VIR_DRV_OPEN_SUCCESS;

declineConnection:
    return VIR_DRV_OPEN_DECLINED;
}

static int lxcClose(virConnectPtr conn)
{
    conn->privateData = NULL;
    return 0;
}

static virDomainPtr lxcDomainLookupByID(virConnectPtr conn,
                                        int id)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    lxc_vm_t *vm = lxcFindVMByID(driver, id);
    virDomainPtr dom;

    if (!vm) {
        lxcError(conn, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) {
        dom->id = vm->def->id;
    }

    return dom;
}

static virDomainPtr lxcDomainLookupByUUID(virConnectPtr conn,
                                          const unsigned char *uuid)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    lxc_vm_t *vm = lxcFindVMByUUID(driver, uuid);
    virDomainPtr dom;

    if (!vm) {
        lxcError(conn, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) {
        dom->id = vm->def->id;
    }

    return dom;
}

static virDomainPtr lxcDomainLookupByName(virConnectPtr conn,
                                          const char *name)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    lxc_vm_t *vm = lxcFindVMByName(driver, name);
    virDomainPtr dom;

    if (!vm) {
        lxcError(conn, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) {
        dom->id = vm->def->id;
    }

    return dom;
}

static int lxcListDomains(virConnectPtr conn, int *ids, int nids)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    lxc_vm_t *vm;
    int numDoms = 0;

    for (vm = driver->vms; vm && (numDoms < nids); vm = vm->next) {
        if (lxcIsActiveVM(vm)) {
            ids[numDoms] = vm->def->id;
            numDoms++;
        }
    }

    return numDoms;
}

static int lxcNumDomains(virConnectPtr conn)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    return driver->nactivevms;
}

static int lxcListDefinedDomains(virConnectPtr conn,
                                 char **const names, int nnames)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    lxc_vm_t *vm;
    int numDoms = 0;
    int i;

    for (vm = driver->vms; vm && (numDoms < nnames); vm = vm->next) {
        if (!lxcIsActiveVM(vm)) {
            if (!(names[numDoms] = strdup(vm->def->name))) {
                lxcError(conn, NULL, VIR_ERR_NO_MEMORY, "names");
                goto cleanup;
            }

            numDoms++;
        }

    }

    return numDoms;

 cleanup:
    for (i = 0 ; i < numDoms ; i++) {
        free(names[i]);
    }

    return -1;
}


static int lxcNumDefinedDomains(virConnectPtr conn)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    return driver->ninactivevms;
}

static virDomainPtr lxcDomainDefine(virConnectPtr conn, const char *xml)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    lxc_vm_def_t *def;
    lxc_vm_t *vm;
    virDomainPtr dom;

    if (!(def = lxcParseVMDef(conn, xml, NULL))) {
        return NULL;
    }

    if (!(vm = lxcAssignVMDef(conn, driver, def))) {
        lxcFreeVMDef(def);
        return NULL;
    }

    if (lxcSaveVMDef(conn, driver, vm, def) < 0) {
        lxcRemoveInactiveVM(driver, vm);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) {
        dom->id = vm->def->id;
    }

    return dom;
}

static int lxcDomainUndefine(virDomainPtr dom)
{
    lxc_driver_t *driver = (lxc_driver_t *)dom->conn->privateData;
    lxc_vm_t *vm = lxcFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with matching uuid"));
        return -1;
    }

    if (lxcIsActiveVM(vm)) {
        lxcError(dom->conn, dom, VIR_ERR_INTERNAL_ERROR,
                 _("cannot delete active domain"));
        return -1;
    }

    if (lxcDeleteConfig(dom->conn, driver, vm->configFile, vm->def->name) < 0) {
        return -1;
    }

    vm->configFile[0] = '\0';

    lxcRemoveInactiveVM(driver, vm);

    return 0;
}

static int lxcDomainGetInfo(virDomainPtr dom,
                            virDomainInfoPtr info)
{
    lxc_driver_t *driver = (lxc_driver_t *)dom->conn->privateData;
    lxc_vm_t *vm = lxcFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with matching uuid"));
        return -1;
    }

    info->state = vm->state;

    if (!lxcIsActiveVM(vm)) {
        info->cpuTime = 0;
    } else {
        info->cpuTime = 0;
    }

    info->maxMem = vm->def->maxMemory;
    info->memory = vm->def->maxMemory;
    info->nrVirtCpu = 1;

    return 0;
}

static char *lxcGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    /* Linux containers only run on Linux */
    return strdup("linux");
}

static char *lxcDomainDumpXML(virDomainPtr dom,
                              int flags ATTRIBUTE_UNUSED)
{
    lxc_driver_t *driver = (lxc_driver_t *)dom->conn->privateData;
    lxc_vm_t *vm = lxcFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with matching uuid"));
        return NULL;
    }

    return lxcGenerateXML(dom->conn, driver, vm, vm->def);
}


static int lxcStartup(void)
{
    uid_t uid = getuid();

    /* Check that the user is root */
    if (0 != uid) {
        return -1;
    }

    lxc_driver = calloc(1, sizeof(lxc_driver_t));
    if (NULL == lxc_driver) {
        return -1;
    }

    /* Check that this is a container enabled kernel */
    if(0 != lxcCheckContainerSupport()) {
        return -1;
    }


    /* Call function to load lxc driver configuration information */
    if (lxcLoadDriverConfig(lxc_driver) < 0) {
        lxcShutdown();
        return -1;
    }

    /* Call function to load the container configuration files */
    if (lxcLoadContainerInfo(lxc_driver) < 0) {
        lxcShutdown();
        return -1;
    }

    return 0;
}

static void lxcFreeDriver(lxc_driver_t *driver)
{
    free(driver->configDir);
    free(driver);
}

static int lxcShutdown(void)
{
    if (lxc_driver == NULL)
        return(-1);
    lxcFreeVMs(lxc_driver->vms);
    lxc_driver->vms = NULL;
    lxcFreeDriver(lxc_driver);
    lxc_driver = NULL;

    return 0;
}

/**
 * lxcActive:
 *
 * Checks if the LXC daemon is active, i.e. has an active domain
 *
 * Returns 1 if active, 0 otherwise
 */
static int
lxcActive(void) {
    if (lxc_driver == NULL)
        return(0);
    /* If we've any active networks or guests, then we
     * mark this driver as active
     */
    if (lxc_driver->nactivevms)
        return 1;

    /* Otherwise we're happy to deal with a shutdown */
    return 0;
}


/* Function Tables */
static virDriver lxcDriver = {
    VIR_DRV_LXC, /* the number virDrvNo */
    "LXC", /* the name of the driver */
    LIBVIR_VERSION_NUMBER, /* the version of the backend */
    lxcProbe, /* probe */
    lxcOpen, /* open */
    lxcClose, /* close */
    NULL, /* supports_feature */
    NULL, /* type */
    NULL, /* version */
    NULL, /* getHostname */
    NULL, /* getURI */
    NULL, /* getMaxVcpus */
    NULL, /* nodeGetInfo */
    NULL, /* getCapabilities */
    lxcListDomains, /* listDomains */
    lxcNumDomains, /* numOfDomains */
    NULL/*lxcDomainCreateLinux*/, /* domainCreateLinux */
    lxcDomainLookupByID, /* domainLookupByID */
    lxcDomainLookupByUUID, /* domainLookupByUUID */
    lxcDomainLookupByName, /* domainLookupByName */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    NULL, /* domainShutdown */
    NULL, /* domainReboot */
    NULL, /* domainDestroy */
    lxcGetOSType, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    lxcDomainGetInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    lxcDomainDumpXML, /* domainDumpXML */
    lxcListDefinedDomains, /* listDefinedDomains */
    lxcNumDefinedDomains, /* numOfDefinedDomains */
    NULL, /* domainCreate */
    lxcDomainDefine, /* domainDefineXML */
    lxcDomainUndefine, /* domainUndefine */
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
    NULL, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
};


static virStateDriver lxcStateDriver = {
    lxcStartup,
    lxcShutdown,
    NULL, /* reload */
    lxcActive,
};

int lxcRegister(void)
{
    virRegisterDriver(&lxcDriver);
    virRegisterStateDriver(&lxcStateDriver);
    return 0;
}

#endif /* WITH_LXC */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
