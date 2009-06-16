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

#include <fcntl.h>
#include <sched.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <unistd.h>
#include <wait.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_driver.h"
#include "memory.h"
#include "util.h"
#include "bridge.h"
#include "veth.h"
#include "event.h"
#include "cgroup.h"
#include "nodeinfo.h"


#define VIR_FROM_THIS VIR_FROM_LXC

static int lxcStartup(int privileged);
static int lxcShutdown(void);
static lxc_driver_t *lxc_driver = NULL;

/* Functions */

static void lxcDriverLock(lxc_driver_t *driver)
{
    virMutexLock(&driver->lock);
}
static void lxcDriverUnlock(lxc_driver_t *driver)
{
    virMutexUnlock(&driver->lock);
}


static virDrvOpenStatus lxcOpen(virConnectPtr conn,
                                virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                int flags ATTRIBUTE_UNUSED)
{
    /* Verify uri was specified */
    if (conn->uri == NULL) {
        if (lxc_driver == NULL)
            return VIR_DRV_OPEN_DECLINED;

        conn->uri = xmlParseURI("lxc:///");
        if (!conn->uri) {
            virReportOOMError(conn);
            return VIR_DRV_OPEN_ERROR;
        }
    } else {
        if (conn->uri->scheme == NULL ||
            STRNEQ(conn->uri->scheme, "lxc"))
            return VIR_DRV_OPEN_DECLINED;

        /* Leave for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* If path isn't '/' then they typoed, tell them correct path */
        if (STRNEQ(conn->uri->path, "/")) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("unexpected LXC URI path '%s', try lxc:///"),
                     conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }

        /* URI was good, but driver isn't active */
        if (lxc_driver == NULL) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("lxc state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    conn->privateData = lxc_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int lxcClose(virConnectPtr conn)
{
    conn->privateData = NULL;
    return 0;
}

static char *lxcGetCapabilities(virConnectPtr conn) {
    lxc_driver_t *driver = conn->privateData;
    char *xml;

    lxcDriverLock(driver);
    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError(conn);
    lxcDriverUnlock(driver);

    return xml;
}


static virDomainPtr lxcDomainLookupByID(virConnectPtr conn,
                                        int id)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, id);
    lxcDriverUnlock(driver);

    if (!vm) {
        lxcError(conn, NULL, VIR_ERR_NO_DOMAIN, NULL);
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

static virDomainPtr lxcDomainLookupByUUID(virConnectPtr conn,
                                          const unsigned char *uuid)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        lxcError(conn, NULL, VIR_ERR_NO_DOMAIN, NULL);
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

static virDomainPtr lxcDomainLookupByName(virConnectPtr conn,
                                          const char *name)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, name);
    lxcDriverUnlock(driver);
    if (!vm) {
        lxcError(conn, NULL, VIR_ERR_NO_DOMAIN, NULL);
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

static int lxcListDomains(virConnectPtr conn, int *ids, int nids) {
    lxc_driver_t *driver = conn->privateData;
    int got = 0, i;

    lxcDriverLock(driver);
    for (i = 0 ; i < driver->domains.count && got < nids ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (virDomainIsActive(driver->domains.objs[i]))
            ids[got++] = driver->domains.objs[i]->def->id;
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    lxcDriverUnlock(driver);

    return got;
}

static int lxcNumDomains(virConnectPtr conn) {
    lxc_driver_t *driver = conn->privateData;
    int n = 0, i;

    lxcDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (virDomainIsActive(driver->domains.objs[i]))
            n++;
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    lxcDriverUnlock(driver);

    return n;
}

static int lxcListDefinedDomains(virConnectPtr conn,
                                 char **const names, int nnames) {
    lxc_driver_t *driver = conn->privateData;
    int got = 0, i;

    lxcDriverLock(driver);
    for (i = 0 ; i < driver->domains.count && got < nnames ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (!virDomainIsActive(driver->domains.objs[i])) {
            if (!(names[got++] = strdup(driver->domains.objs[i]->def->name))) {
                virReportOOMError(conn);
                virDomainObjUnlock(driver->domains.objs[i]);
                goto cleanup;
            }
        }
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    lxcDriverUnlock(driver);

    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    lxcDriverUnlock(driver);
    return -1;
}


static int lxcNumDefinedDomains(virConnectPtr conn) {
    lxc_driver_t *driver = conn->privateData;
    int n = 0, i;

    lxcDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (!virDomainIsActive(driver->domains.objs[i]))
            n++;
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    lxcDriverUnlock(driver);

    return n;
}



static virDomainPtr lxcDomainDefine(virConnectPtr conn, const char *xml)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    if (!(def = virDomainDefParseString(conn, driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if ((def->nets != NULL) && !(driver->have_netns)) {
        lxcError(conn, NULL, VIR_ERR_NO_SUPPORT,
                 "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    if (!(vm = virDomainAssignDef(conn, &driver->domains, def)))
        goto cleanup;
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(conn,
                            driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return dom;
}

static int lxcDomainUndefine(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        lxcError(dom->conn, dom, VIR_ERR_OPERATION_INVALID,
                 "%s", _("cannot delete active domain"));
        goto cleanup;
    }

    if (!vm->persistent) {
        lxcError(dom->conn, dom, VIR_ERR_OPERATION_INVALID,
                 "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(dom->conn,
                              driver->configDir,
                              driver->autostartDir,
                              vm) < 0)
        goto cleanup;

    virDomainRemoveInactive(&driver->domains, vm);
    vm = NULL;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int lxcDomainGetInfo(virDomainPtr dom,
                            virDomainInfoPtr info)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virCgroupPtr cgroup = NULL;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm) || virCgroupHaveSupport() != 0) {
        info->cpuTime = 0;
    } else {
        if (virCgroupForDomain(vm->def, "lxc", &cgroup) != 0) {
            lxcError(dom->conn, dom, VIR_ERR_INTERNAL_ERROR,
                     _("Unable to get cgroup for %s\n"), vm->def->name);
            goto cleanup;
        }

        if (virCgroupGetCpuacctUsage(cgroup, &(info->cpuTime)) < 0) {
            lxcError(dom->conn, dom, VIR_ERR_OPERATION_FAILED, ("cannot read cputime for domain"));
            goto cleanup;
        }
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = 1;
    ret = 0;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static char *lxcGetOSType(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = strdup(vm->def->os.type);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static char *lxcDomainDumpXML(virDomainPtr dom,
                              int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(dom->conn,
                             (flags & VIR_DOMAIN_XML_INACTIVE) &&
                             vm->newDef ? vm->newDef : vm->def,
                             flags);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


/**
 * lxcVmCleanup:
 * @vm: Ptr to VM to clean up
 *
 * waitpid() on the container process.  kill and wait the tty process
 * This is called by both lxcDomainDestroy and lxcSigHandler when a
 * container exits.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcVMCleanup(virConnectPtr conn,
                        lxc_driver_t *driver,
                        virDomainObjPtr  vm)
{
    int rc = -1;
    int waitRc;
    int childStatus = -1;
    virCgroupPtr cgroup;
    int i;

    while (((waitRc = waitpid(vm->pid, &childStatus, 0)) == -1) &&
           errno == EINTR)
        ; /* empty */

    if ((waitRc != vm->pid) && (errno != ECHILD)) {
        virReportSystemError(conn, errno,
                             _("waitpid failed to wait for container %d: %d"),
                             vm->pid, waitRc);
    }

    rc = 0;

    if (WIFEXITED(childStatus)) {
        rc = WEXITSTATUS(childStatus);
        DEBUG("container exited with rc: %d", rc);
    }

    virEventRemoveHandle(vm->monitorWatch);
    close(vm->monitor);

    virFileDeletePid(driver->stateDir, vm->def->name);
    virDomainDeleteConfig(conn, driver->stateDir, NULL, vm);

    vm->state = VIR_DOMAIN_SHUTOFF;
    vm->pid = -1;
    vm->def->id = -1;
    vm->monitor = -1;

    for (i = 0 ; i < vm->def->nnets ; i++) {
        vethInterfaceUpOrDown(vm->def->nets[i]->ifname, 0);
        vethDelete(vm->def->nets[i]->ifname);
    }

    if (virCgroupForDomain(vm->def, "lxc", &cgroup) == 0) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }

    return rc;
}

/**
 * lxcSetupInterfaces:
 * @def: pointer to virtual machine structure
 *
 * Sets up the container interfaces by creating the veth device pairs and
 * attaching the parent end to the appropriate bridge.  The container end
 * will moved into the container namespace later after clone has been called.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcSetupInterfaces(virConnectPtr conn,
                              virDomainDefPtr def,
                              unsigned int *nveths,
                              char ***veths)
{
    int rc = -1, i;
    char *bridge = NULL;
    char parentVeth[PATH_MAX] = "";
    char containerVeth[PATH_MAX] = "";
    brControl *brctl = NULL;

    if (brInit(&brctl) != 0)
        return -1;

    for (i = 0 ; i < def->nnets ; i++) {
        switch (def->nets[i]->type) {
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        {
            virNetworkPtr network = virNetworkLookupByName(conn,
                                                           def->nets[i]->data.network.name);
            if (!network) {
                goto error_exit;
            }

            bridge = virNetworkGetBridgeName(network);

            virNetworkFree(network);
            break;
        }
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            bridge = def->nets[i]->data.bridge.brname;
            break;
        }

        DEBUG("bridge: %s", bridge);
        if (NULL == bridge) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     "%s", _("failed to get bridge for interface"));
            goto error_exit;
        }

        DEBUG0("calling vethCreate()");
        if (NULL != def->nets[i]->ifname) {
            strcpy(parentVeth, def->nets[i]->ifname);
        }
        DEBUG("parentVeth: %s, containerVeth: %s", parentVeth, containerVeth);
        if (0 != (rc = vethCreate(parentVeth, PATH_MAX, containerVeth, PATH_MAX))) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to create veth device pair: %d"), rc);
            goto error_exit;
        }
        if (NULL == def->nets[i]->ifname) {
            def->nets[i]->ifname = strdup(parentVeth);
        }
        if (VIR_REALLOC_N(*veths, (*nveths)+1) < 0)
            goto error_exit;
        if (((*veths)[(*nveths)++] = strdup(containerVeth)) == NULL)
            goto error_exit;

        if (NULL == def->nets[i]->ifname) {
            lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     "%s", _("failed to allocate veth names"));
            goto error_exit;
        }

        if (0 != (rc = brAddInterface(brctl, bridge, parentVeth))) {
            virReportSystemError(conn, rc,
                                 _("failed to add %s device to %s"),
                                 parentVeth, bridge);
            goto error_exit;
        }

        if (0 != (rc = vethInterfaceUpOrDown(parentVeth, 1))) {
            virReportSystemError(conn, rc, "%s",
                                 _("failed to enable parent ns veth device"));
            goto error_exit;
        }

    }

    rc = 0;

error_exit:
    brShutdown(brctl);
    return rc;
}


static int lxcMonitorClient(virConnectPtr conn,
                            lxc_driver_t * driver,
                            virDomainObjPtr vm)
{
    char *sockpath = NULL;
    int fd;
    struct sockaddr_un addr;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    driver->stateDir, vm->def->name) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(conn, errno, "%s",
                             _("failed to create client socket"));
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path));

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        virReportSystemError(conn, errno, "%s",
                             _("failed to connect to client socket"));
        goto error;
    }

    VIR_FREE(sockpath);
    return fd;

error:
    VIR_FREE(sockpath);
    if (fd != -1)
        close(fd);
    return -1;
}


static int lxcVmTerminate(virConnectPtr conn,
                          lxc_driver_t *driver,
                          virDomainObjPtr vm,
                          int signum)
{
    if (signum == 0)
        signum = SIGINT;

    if (vm->pid <= 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("invalid PID %d for container"), vm->pid);
        return -1;
    }

    if (kill(vm->pid, signum) < 0) {
        if (errno != ESRCH) {
            virReportSystemError(conn, errno,
                                 _("failed to kill pid %d"),
                                 vm->pid);
            return -1;
        }
    }

    vm->state = VIR_DOMAIN_SHUTDOWN;

    return lxcVMCleanup(conn, driver, vm);
}

static void lxcMonitorEvent(int watch,
                            int fd,
                            int events ATTRIBUTE_UNUSED,
                            void *data)
{
    lxc_driver_t *driver = data;
    virDomainObjPtr vm = NULL;
    unsigned int i;

    lxcDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjPtr tmpvm = driver->domains.objs[i];
        virDomainObjLock(tmpvm);
        if (tmpvm->monitorWatch == watch) {
            vm = tmpvm;
            break;
        }
        virDomainObjUnlock(tmpvm);
    }
    if (!vm) {
        virEventRemoveHandle(watch);
        goto cleanup;
    }

    if (vm->monitor != fd) {
        virEventRemoveHandle(watch);
        goto cleanup;
    }

    if (lxcVmTerminate(NULL, driver, vm, SIGINT) < 0)
        virEventRemoveHandle(watch);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
}


static int lxcControllerStart(virConnectPtr conn,
                              virDomainObjPtr vm,
                              int nveths,
                              char **veths,
                              int appPty,
                              int logfd)
{
    int i;
    int rc;
    int ret = -1;
    int largc = 0, larga = 0;
    const char **largv = NULL;
    pid_t child;
    int status;
    fd_set keepfd;
    char appPtyStr[30];
    const char *emulator;

    FD_ZERO(&keepfd);

#define ADD_ARG_SPACE                                                   \
    do { \
        if (largc == larga) {                                           \
            larga += 10;                                                \
            if (VIR_REALLOC_N(largv, larga) < 0)                        \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

#define ADD_ARG(thisarg)                                                \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        largv[largc++] = thisarg;                                       \
    } while (0)

#define ADD_ARG_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        if ((largv[largc++] = strdup(thisarg)) == NULL)                 \
            goto no_memory;                                             \
    } while (0)

    snprintf(appPtyStr, sizeof(appPtyStr), "%d", appPty);

    emulator = vm->def->emulator;

    ADD_ARG_LIT(emulator);
    ADD_ARG_LIT("--name");
    ADD_ARG_LIT(vm->def->name);
    ADD_ARG_LIT("--console");
    ADD_ARG_LIT(appPtyStr);
    ADD_ARG_LIT("--background");

    for (i = 0 ; i < nveths ; i++) {
        ADD_ARG_LIT("--veth");
        ADD_ARG_LIT(veths[i]);
    }

    ADD_ARG(NULL);

    FD_SET(appPty, &keepfd);

    if (virExec(conn, largv, NULL, &keepfd, &child,
                -1, &logfd, &logfd,
                VIR_EXEC_NONE) < 0)
        goto cleanup;

    /* We now wait for the process to exit - the controller
     * will fork() itself into the background - waiting for
     * it to exit thus guarentees it has written its pidfile
     */
    while ((rc = waitpid(child, &status, 0) == -1) && errno == EINTR);
    if (rc == -1) {
        virReportSystemError(conn, errno,
                             _("cannot wait for '%s'"),
                             largv[0]);
        goto cleanup;
    }

    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("container '%s' unexpectedly shutdown during startup"),
                 largv[0]);
        goto cleanup;
    }

#undef ADD_ARG
#undef ADD_ARG_LIT
#undef ADD_ARG_SPACE

    ret = 0;

cleanup:
    for (i = 0 ; i < largc ; i++)
        VIR_FREE(largv[i]);

    return ret;

no_memory:
    virReportOOMError(conn);
    goto cleanup;
}


/**
 * lxcVmStart:
 * @conn: pointer to connection
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 *
 * Starts a vm
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcVmStart(virConnectPtr conn,
                      lxc_driver_t * driver,
                      virDomainObjPtr  vm)
{
    int rc = -1;
    unsigned int i;
    int parentTty;
    char *parentTtyPath = NULL;
    char *logfile = NULL;
    int logfd = -1;
    unsigned int nveths = 0;
    char **veths = NULL;

    if ((rc = virFileMakePath(driver->logDir)) < 0) {
        virReportSystemError(conn, rc,
                             _("cannot create log directory '%s'"),
                             driver->logDir);
        return -1;
    }

    if (virAsprintf(&logfile, "%s/%s.log",
                    driver->logDir, vm->def->name) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    /* open parent tty */
    if (virFileOpenTty(&parentTty, &parentTtyPath, 1) < 0) {
        virReportSystemError(conn, errno, "%s",
                             _("failed to allocate tty"));
        goto cleanup;
    }
    if (vm->def->console &&
        vm->def->console->type == VIR_DOMAIN_CHR_TYPE_PTY) {
        VIR_FREE(vm->def->console->data.file.path);
        vm->def->console->data.file.path = parentTtyPath;
    } else {
        VIR_FREE(parentTtyPath);
    }

    if (lxcSetupInterfaces(conn, vm->def, &nveths, &veths) != 0)
        goto cleanup;

    /* Persist the live configuration now we have veth & tty info */
    if (virDomainSaveConfig(conn, driver->stateDir, vm->def) < 0) {
        rc = -1;
        goto cleanup;
    }

    if ((logfd = open(logfile, O_WRONLY | O_TRUNC | O_CREAT,
             S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(conn, errno,
                             _("failed to open '%s'"),
                             logfile);
        goto cleanup;
    }

    if (lxcControllerStart(conn,
                           vm,
                           nveths, veths,
                           parentTty, logfd) < 0)
        goto cleanup;

    /* Connect to the controller as a client *first* because
     * this will block until the child has written their
     * pid file out to disk */
    if ((vm->monitor = lxcMonitorClient(conn, driver, vm)) < 0)
        goto cleanup;

    /* And get its pid */
    if ((rc = virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) != 0) {
        virReportSystemError(conn, rc,
                             _("Failed to read pid file %s/%s.pid"),
                             driver->stateDir, vm->def->name);
        rc = -1;
        goto cleanup;
    }

    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;

    if ((vm->monitorWatch = virEventAddHandle(
             vm->monitor,
             VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP,
             lxcMonitorEvent,
             driver, NULL)) < 0) {
        lxcVmTerminate(conn, driver, vm, 0);
        goto cleanup;
    }

    rc = 0;

cleanup:
    for (i = 0 ; i < nveths ; i++) {
        if (rc != 0)
            vethDelete(veths[i]);
        VIR_FREE(veths[i]);
    }
    if (rc != 0 && vm->monitor != -1) {
        close(vm->monitor);
        vm->monitor = -1;
    }
    if (parentTty != -1)
        close(parentTty);
    if (logfd != -1)
        close(logfd);
    VIR_FREE(logfile);
    return rc;
}

/**
 * lxcDomainStart:
 * @dom: domain to start
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainStart(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dom->name);
    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain named %s"), dom->name);
        goto cleanup;
    }

    if ((vm->def->nets != NULL) && !(driver->have_netns)) {
        lxcError(dom->conn, NULL, VIR_ERR_NO_SUPPORT,
                 "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    ret = lxcVmStart(dom->conn, driver, vm);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

/**
 * lxcDomainCreateAndStart:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @flags: Unused
 *
 * Creates a domain based on xml and starts it
 *
 * Returns 0 on success or -1 in case of error
 */
static virDomainPtr
lxcDomainCreateAndStart(virConnectPtr conn,
                        const char *xml,
                        unsigned int flags ATTRIBUTE_UNUSED) {
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    if (!(def = virDomainDefParseString(conn, driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if ((def->nets != NULL) && !(driver->have_netns)) {
        lxcError(conn, NULL, VIR_ERR_NO_SUPPORT,
                 "%s", _("System lacks NETNS support"));
        goto cleanup;
    }


    if (!(vm = virDomainAssignDef(conn, &driver->domains, def)))
        goto cleanup;
    def = NULL;

    if (lxcVmStart(conn, driver, vm) < 0) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return dom;
}

/**
 * lxcDomainShutdown:
 * @dom: Ptr to domain to shutdown
 *
 * Sends SIGINT to container root process to request it to shutdown
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainShutdown(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with id %d"), dom->id);
        goto cleanup;
    }

    ret = lxcVmTerminate(dom->conn, driver, vm, 0);
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}


/**
 * lxcDomainDestroy:
 * @dom: Ptr to domain to destroy
 *
 * Sends SIGKILL to container root process to terminate the container
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainDestroy(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with id %d"), dom->id);
        goto cleanup;
    }

    ret = lxcVmTerminate(dom->conn, driver, vm, SIGKILL);
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int lxcCheckNetNsSupport(void)
{
    const char *argv[] = {"ip", "link", "set", "lo", "netns", "-1", NULL};
    int ip_rc;

    if (virRun(NULL, argv, &ip_rc) < 0 ||
        !(WIFEXITED(ip_rc) && (WEXITSTATUS(ip_rc) != 255)))
        return 0;

    if (lxcContainerAvailable(LXC_CONTAINER_FEATURE_NET) < 0)
        return 0;

    return 1;
}

static int lxcStartup(int privileged)
{
    unsigned int i;
    char *ld;

    /* Valgrind gets very annoyed when we clone containers, so
     * disable LXC when under valgrind
     * XXX remove this when valgrind is fixed
     */
    ld = getenv("LD_PRELOAD");
    if (ld && strstr(ld, "vgpreload"))
        return -1;

    /* Check that the user is root */
    if (!privileged) {
        return -1;
    }

    if (VIR_ALLOC(lxc_driver) < 0) {
        return -1;
    }
    if (virMutexInit(&lxc_driver->lock) < 0) {
        VIR_FREE(lxc_driver);
        return -1;
    }
    lxcDriverLock(lxc_driver);

    /* Check that this is a container enabled kernel */
    if(lxcContainerAvailable(0) < 0)
        goto cleanup;

    lxc_driver->have_netns = lxcCheckNetNsSupport();

    /* Call function to load lxc driver configuration information */
    if (lxcLoadDriverConfig(lxc_driver) < 0)
        goto cleanup;

    if ((lxc_driver->caps = lxcCapsInit()) == NULL)
        goto cleanup;

    if (virDomainLoadAllConfigs(NULL,
                                lxc_driver->caps,
                                &lxc_driver->domains,
                                lxc_driver->configDir,
                                lxc_driver->autostartDir,
                                0, NULL, NULL) < 0)
        goto cleanup;

    for (i = 0 ; i < lxc_driver->domains.count ; i++) {
        virDomainObjPtr vm = lxc_driver->domains.objs[i];
        char *config = NULL;
        virDomainDefPtr tmp;
        int rc;

        virDomainObjLock(vm);
        if ((vm->monitor = lxcMonitorClient(NULL, lxc_driver, vm)) < 0) {
            virDomainObjUnlock(vm);
            continue;
        }

        /* Read pid from controller */
        if ((rc = virFileReadPid(lxc_driver->stateDir, vm->def->name, &vm->pid)) != 0) {
            close(vm->monitor);
            vm->monitor = -1;
            virDomainObjUnlock(vm);
            continue;
        }

        if ((config = virDomainConfigFile(NULL,
                                          lxc_driver->stateDir,
                                          vm->def->name)) == NULL) {
            virDomainObjUnlock(vm);
            continue;
        }

        /* Try and load the live config */
        tmp = virDomainDefParseFile(NULL, lxc_driver->caps, config, 0);
        VIR_FREE(config);
        if (tmp) {
            vm->newDef = vm->def;
            vm->def = tmp;
        }

        if (vm->pid != 0) {
            vm->def->id = vm->pid;
            vm->state = VIR_DOMAIN_RUNNING;
        } else {
            vm->def->id = -1;
            close(vm->monitor);
            vm->monitor = -1;
        }
        virDomainObjUnlock(vm);
    }

    lxcDriverUnlock(lxc_driver);
    return 0;

cleanup:
    lxcDriverUnlock(lxc_driver);
    lxcShutdown();
    return -1;
}

static int lxcShutdown(void)
{
    if (lxc_driver == NULL)
        return(-1);

    lxcDriverLock(lxc_driver);
    virDomainObjListFree(&lxc_driver->domains);

    virCapabilitiesFree(lxc_driver->caps);
    VIR_FREE(lxc_driver->configDir);
    VIR_FREE(lxc_driver->autostartDir);
    VIR_FREE(lxc_driver->stateDir);
    VIR_FREE(lxc_driver->logDir);
    lxcDriverUnlock(lxc_driver);
    virMutexDestroy(&lxc_driver->lock);
    VIR_FREE(lxc_driver);

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
    unsigned int i;
    int active = 0;

    if (lxc_driver == NULL)
        return(0);

    lxcDriverLock(lxc_driver);
    for (i = 0 ; i < lxc_driver->domains.count ; i++) {
        virDomainObjLock(lxc_driver->domains.objs[i]);
        if (virDomainIsActive(lxc_driver->domains.objs[i]))
            active = 1;
        virDomainObjUnlock(lxc_driver->domains.objs[i]);
    }
    lxcDriverUnlock(lxc_driver);

    return active;
}

static int lxcVersion(virConnectPtr conn, unsigned long *version)
{
    struct utsname ver;
    int maj;
    int min;
    int rev;

    uname(&ver);

    if (sscanf(ver.release, "%i.%i.%i", &maj, &min, &rev) != 3) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Unknown release: %s"), ver.release);
        return -1;
    }

    *version = (maj * 1000 * 1000) + (min * 1000) + rev;

    return 0;
}

static char *lxcGetSchedulerType(virDomainPtr domain ATTRIBUTE_UNUSED,
                                 int *nparams)
{
    if (nparams)
        *nparams = 1;

    return strdup("posix");
}

static int lxcSetSchedulerParameters(virDomainPtr domain,
                                     virSchedParameterPtr params,
                                     int nparams)
{
    lxc_driver_t *driver = domain->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    if (virCgroupHaveSupport() != 0)
        return -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    lxcDriverUnlock(driver);

    if (vm == NULL) {
        lxcError(NULL, domain, VIR_ERR_INTERNAL_ERROR,
                 _("No such domain %s"), domain->uuid);
        goto cleanup;
    }

    if (virCgroupForDomain(vm->def, "lxc", &group) != 0)
        goto cleanup;

    for (i = 0; i < nparams; i++) {
        virSchedParameterPtr param = &params[i];

        if (STREQ(param->field, "cpu_shares")) {
            if (virCgroupSetCpuShares(group, params[i].value.ui) != 0)
                goto cleanup;
        } else {
            lxcError(NULL, domain, VIR_ERR_INVALID_ARG,
                     _("Invalid parameter `%s'"), param->field);
            goto cleanup;
        }
    }
    ret = 0;

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int lxcGetSchedulerParameters(virDomainPtr domain,
                                     virSchedParameterPtr params,
                                     int *nparams)
{
    lxc_driver_t *driver = domain->conn->privateData;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long val;
    int ret = -1;

    if (virCgroupHaveSupport() != 0)
        return -1;

    if ((*nparams) != 1) {
        lxcError(NULL, domain, VIR_ERR_INVALID_ARG,
                 "%s", _("Invalid parameter count"));
        return -1;
    }

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    lxcDriverUnlock(driver);

    if (vm == NULL) {
        lxcError(NULL, domain, VIR_ERR_INTERNAL_ERROR,
                 _("No such domain %s"), domain->uuid);
        goto cleanup;
    }

    if (virCgroupForDomain(vm->def, "lxc", &group) != 0)
        goto cleanup;

    if (virCgroupGetCpuShares(group, &val) != 0)
        goto cleanup;
    params[0].value.ul = val;
    strncpy(params[0].field, "cpu_shares", sizeof(params[0].field));
    params[0].type = VIR_DOMAIN_SCHED_FIELD_ULLONG;

    ret = 0;

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static char *lxcGetHostname (virConnectPtr conn)
{
    char *result;

    result = virGetHostname();
    if (result == NULL) {
        virReportSystemError (conn, errno,
                              "%s", _("failed to determine host name"));
        return NULL;
    }
    /* Caller frees this string. */
    return result;
}

/* Function Tables */
static virDriver lxcDriver = {
    VIR_DRV_LXC, /* the number virDrvNo */
    "LXC", /* the name of the driver */
    lxcOpen, /* open */
    lxcClose, /* close */
    NULL, /* supports_feature */
    NULL, /* type */
    lxcVersion, /* version */
    lxcGetHostname, /* getHostname */
    NULL, /* getMaxVcpus */
    nodeGetInfo, /* nodeGetInfo */
    lxcGetCapabilities, /* getCapabilities */
    lxcListDomains, /* listDomains */
    lxcNumDomains, /* numOfDomains */
    lxcDomainCreateAndStart, /* domainCreateXML */
    lxcDomainLookupByID, /* domainLookupByID */
    lxcDomainLookupByUUID, /* domainLookupByUUID */
    lxcDomainLookupByName, /* domainLookupByName */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    lxcDomainShutdown, /* domainShutdown */
    NULL, /* domainReboot */
    lxcDomainDestroy, /* domainDestroy */
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
    NULL, /* domainGetSecurityLabel */
    NULL, /* nodeGetSecurityModel */
    lxcDomainDumpXML, /* domainDumpXML */
    NULL, /* domainXmlFromNative */
    NULL, /* domainXmlToNative */
    lxcListDefinedDomains, /* listDefinedDomains */
    lxcNumDefinedDomains, /* numOfDefinedDomains */
    lxcDomainStart, /* domainCreate */
    lxcDomainDefine, /* domainDefineXML */
    lxcDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
    lxcGetSchedulerType, /* domainGetSchedulerType */
    lxcGetSchedulerParameters, /* domainGetSchedulerParameters */
    lxcSetSchedulerParameters, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare */
    NULL, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    NULL, /* domainBlockStats */
    NULL, /* domainInterfaceStats */
    NULL, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    nodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    nodeGetFreeMemory,  /* getFreeMemory */
    NULL, /* domainEventRegister */
    NULL, /* domainEventDeregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
    NULL, /* nodeDeviceDettach */
    NULL, /* nodeDeviceReAttach */
    NULL, /* nodeDeviceReset */
};

static virStateDriver lxcStateDriver = {
    .initialize = lxcStartup,
    .cleanup = lxcShutdown,
    .active = lxcActive,
};

int lxcRegister(void)
{
    virRegisterDriver(&lxcDriver);
    virRegisterStateDriver(&lxcStateDriver);
    return 0;
}
