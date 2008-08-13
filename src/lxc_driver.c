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

#include "internal.h"
#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_driver.h"
#include "lxc_controller.h"
#include "memory.h"
#include "util.h"
#include "bridge.h"
#include "veth.h"
#include "event.h"


/* debug macros */
#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)


static int lxcStartup(void);
static int lxcShutdown(void);
static lxc_driver_t *lxc_driver = NULL;

/* Functions */

static const char *lxcProbe(void)
{
    if (lxcContainerAvailable(0) < 0)
        return NULL;

    return("lxc:///");
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
        VIR_FREE(names[i]);
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

    if ((def->nets != NULL) && !(driver->have_netns)) {
        lxcError(conn, NULL, VIR_ERR_NO_SUPPORT,
                 _("System lacks NETNS support"));
        lxcFreeVMDef(def);
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
                        lxc_vm_t * vm)
{
    int rc = -1;
    int waitRc;
    int childStatus = -1;

    while (((waitRc = waitpid(vm->pid, &childStatus, 0)) == -1) &&
           errno == EINTR)
        ; /* empty */

    if ((waitRc != vm->pid) && (errno != ECHILD)) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("waitpid failed to wait for container %d: %d %s"),
                 vm->pid, waitRc, strerror(errno));
    }

    rc = 0;

    if (WIFEXITED(childStatus)) {
        rc = WEXITSTATUS(childStatus);
        DEBUG("container exited with rc: %d", rc);
    }

    virEventRemoveHandle(vm->monitor);
    close(vm->monitor);

    virFileDeletePid(driver->stateDir, vm->def->name);

    vm->state = VIR_DOMAIN_SHUTOFF;
    vm->pid = -1;
    vm->def->id = -1;
    vm->monitor = -1;
    driver->nactivevms--;
    driver->ninactivevms++;

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
                              lxc_vm_def_t *def,
                              unsigned int *nveths,
                              char ***veths)
{
    int rc = -1;
    lxc_net_def_t *net;
    char *bridge = NULL;
    char parentVeth[PATH_MAX] = "";
    char containerVeth[PATH_MAX] = "";
    brControl *brctl = NULL;

    if (brInit(&brctl) != 0)
        return -1;

    for (net = def->nets; net; net = net->next) {
        if (LXC_NET_NETWORK == net->type) {
            virNetworkPtr network = virNetworkLookupByName(conn, net->txName);
            if (!network) {
                goto error_exit;
            }

            bridge = virNetworkGetBridgeName(network);

            virNetworkFree(network);
        } else {
            bridge = net->txName;
        }

        DEBUG("bridge: %s", bridge);
        if (NULL == bridge) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to get bridge for interface"));
            goto error_exit;
        }

        DEBUG0("calling vethCreate()");
        if (NULL != net->parentVeth) {
            strcpy(parentVeth, net->parentVeth);
        }
        DEBUG("parentVeth: %s, containerVeth: %s", parentVeth, containerVeth);
        if (0 != (rc = vethCreate(parentVeth, PATH_MAX, containerVeth, PATH_MAX))) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to create veth device pair: %d"), rc);
            goto error_exit;
        }
        if (NULL == net->parentVeth) {
            net->parentVeth = strdup(parentVeth);
        }
        if (VIR_REALLOC_N(*veths, (*nveths)+1) < 0)
            goto error_exit;
        if (((*veths)[(*nveths)++] = strdup(containerVeth)) == NULL)
            goto error_exit;

        if (NULL == net->parentVeth) {
            lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to allocate veth names"));
            goto error_exit;
        }

        if (0 != (rc = brAddInterface(brctl, bridge, parentVeth))) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to add %s device to %s: %s"),
                     parentVeth,
                     bridge,
                     strerror(rc));
            goto error_exit;
        }

        if (0 != (rc = vethInterfaceUpOrDown(parentVeth, 1))) {
            lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to enable parent ns veth device: %d"), rc);
            goto error_exit;
        }

    }

    rc = 0;

error_exit:
    brShutdown(brctl);
    return rc;
}

static int lxcMonitorServer(virConnectPtr conn,
                            lxc_driver_t * driver,
                            lxc_vm_t *vm)
{
    char *sockpath = NULL;
    int fd;
    struct sockaddr_un addr;

    if (asprintf(&sockpath, "%s/%s.sock",
                 driver->stateDir, vm->def->name) < 0) {
        lxcError(conn, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to create server socket: %s"),
                 strerror(errno));
        goto error;
    }

    unlink(sockpath);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path));

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to bind server socket: %s"),
                 strerror(errno));
        goto error;
    }
    if (listen(fd, 30 /* backlog */ ) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to listen server socket: %s"),
                 strerror(errno));
        goto error;
        return (-1);
    }

    VIR_FREE(sockpath);
    return fd;

error:
    VIR_FREE(sockpath);
    if (fd != -1)
        close(fd);
    return -1;
}

static int lxcMonitorClient(virConnectPtr conn,
                            lxc_driver_t * driver,
                            lxc_vm_t *vm)
{
    char *sockpath = NULL;
    int fd;
    struct sockaddr_un addr;

    if (asprintf(&sockpath, "%s/%s.sock",
                 driver->stateDir, vm->def->name) < 0) {
        lxcError(conn, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to create client socket: %s"),
                 strerror(errno));
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path));

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to connect to client socket: %s"),
                 strerror(errno));
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
                          lxc_vm_t *vm,
                          int signum)
{
    if (signum == 0)
        signum = SIGINT;

    if (kill(vm->pid, signum) < 0) {
        if (errno != ESRCH) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to kill pid %d: %s"),
                     vm->pid, strerror(errno));
            return -1;
        }
    }

    vm->state = VIR_DOMAIN_SHUTDOWN;

    return lxcVMCleanup(conn, driver, vm);
}

static void lxcMonitorEvent(int fd,
                            int events ATTRIBUTE_UNUSED,
                            void *data)
{
    lxc_driver_t *driver = data;
    lxc_vm_t *vm = driver->vms;

    while (vm) {
        if (vm->monitor == fd)
            break;
        vm = vm->next;
    }
    if (!vm) {
        virEventRemoveHandle(fd);
        return;
    }

    if (lxcVmTerminate(NULL, driver, vm, SIGINT) < 0)
        virEventRemoveHandle(fd);
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
                      lxc_vm_t * vm)
{
    int rc = -1;
    unsigned int i;
    int monitor;
    int parentTty;
    char *logfile = NULL;
    int logfd = -1;
    unsigned int nveths = 0;
    char **veths = NULL;

    if (virFileMakePath(driver->logDir) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("cannot create log directory %s: %s"),
                 driver->logDir, strerror(rc));
        return -1;
    }

    if (asprintf(&logfile, "%s/%s.log",
                 driver->logDir, vm->def->name) < 0) {
        lxcError(conn, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    if ((monitor = lxcMonitorServer(conn, driver, vm)) < 0)
        goto cleanup;

    /* open parent tty */
    VIR_FREE(vm->def->tty);
    if (virFileOpenTty(&parentTty, &vm->def->tty, 1) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to allocate tty: %s"),
                 strerror(errno));
        goto cleanup;
    }

    if (lxcSetupInterfaces(conn, vm->def, &nveths, &veths) != 0)
        goto cleanup;

    if ((logfd = open(logfile, O_WRONLY | O_TRUNC | O_CREAT,
             S_IRUSR|S_IWUSR)) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to open %s: %s"), logfile,
                 strerror(errno));
        goto cleanup;
    }

    if (lxcControllerStart(driver->stateDir,
                           vm->def, nveths, veths,
                           monitor, parentTty, logfd) < 0)
        goto cleanup;
    /* Close the server side of the monitor, now owned
     * by the controller process */
    close(monitor);
    monitor = -1;

    /* Connect to the controller as a client *first* because
     * this will block until the child has written their
     * pid file out to disk */
    if ((vm->monitor = lxcMonitorClient(conn, driver, vm)) < 0)
        goto cleanup;

    /* And get its pid */
    if ((rc = virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) != 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Failed to read pid file %s/%s.pid: %s"),
                 driver->stateDir, vm->def->name, strerror(rc));
        rc = -1;
        goto cleanup;
    }

    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;
    driver->ninactivevms--;
    driver->nactivevms++;

    if (virEventAddHandle(vm->monitor,
                          POLLERR | POLLHUP,
                          lxcMonitorEvent,
                          driver) < 0) {
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
    if (monitor != -1)
        close(monitor);
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
    int rc = -1;
    virConnectPtr conn = dom->conn;
    lxc_driver_t *driver = (lxc_driver_t *)(conn->privateData);
    lxc_vm_t *vm = lxcFindVMByName(driver, dom->name);

    if (!vm) {
        lxcError(conn, dom, VIR_ERR_INVALID_DOMAIN,
                 "no domain with uuid");
        goto cleanup;
    }

    rc = lxcVmStart(conn, driver, vm);

cleanup:
    return rc;
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
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    lxc_vm_t *vm;
    lxc_vm_def_t *def;
    virDomainPtr dom = NULL;

    if (!(def = lxcParseVMDef(conn, xml, NULL))) {
        goto return_point;
    }

    if (!(vm = lxcAssignVMDef(conn, driver, def))) {
        lxcFreeVMDef(def);
        goto return_point;
    }

    if (lxcSaveVMDef(conn, driver, vm, def) < 0) {
        lxcRemoveInactiveVM(driver, vm);
        return NULL;
    }

    if (lxcVmStart(conn, driver, vm) < 0) {
        lxcRemoveInactiveVM(driver, vm);
        goto return_point;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) {
        dom->id = vm->def->id;
    }

return_point:
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
    lxc_driver_t *driver = (lxc_driver_t*)dom->conn->privateData;
    lxc_vm_t *vm = lxcFindVMByID(driver, dom->id);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with id %d"), dom->id);
        return -1;
    }

    return lxcVmTerminate(dom->conn, driver, vm, 0);
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
    lxc_driver_t *driver = (lxc_driver_t*)dom->conn->privateData;
    lxc_vm_t *vm = lxcFindVMByID(driver, dom->id);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with id %d"), dom->id);
        return -1;
    }

    return lxcVmTerminate(dom->conn, driver, vm, SIGKILL);
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

static int lxcStartup(void)
{
    uid_t uid = getuid();
    lxc_vm_t *vm;

    /* Check that the user is root */
    if (0 != uid) {
        return -1;
    }

    if (VIR_ALLOC(lxc_driver) < 0) {
        return -1;
    }

    /* Check that this is a container enabled kernel */
    if(lxcContainerAvailable(0) < 0)
        return -1;

    lxc_driver->have_netns = lxcCheckNetNsSupport();

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

    vm = lxc_driver->vms;
    while (vm) {
        int rc;
        if ((vm->monitor = lxcMonitorClient(NULL, lxc_driver, vm)) < 0) {
            vm = vm->next;
            continue;
        }

        /* Read pid from controller */
        if ((rc = virFileReadPid(lxc_driver->stateDir, vm->def->name, &vm->pid)) != 0) {
            close(vm->monitor);
            vm->monitor = -1;
            vm = vm->next;
            continue;
        }

        if (vm->pid != 0) {
            vm->def->id = vm->pid;
            vm->state = VIR_DOMAIN_RUNNING;
            lxc_driver->ninactivevms--;
            lxc_driver->nactivevms++;
        } else {
            vm->def->id = -1;
            close(vm->monitor);
            vm->monitor = -1;
        }

        vm = vm->next;
    }

    return 0;
}

static void lxcFreeDriver(lxc_driver_t *driver)
{
    VIR_FREE(driver->configDir);
    VIR_FREE(driver->stateDir);
    VIR_FREE(driver->logDir);
    VIR_FREE(driver);
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
    lxcDomainCreateAndStart, /* domainCreateLinux */
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
    lxcDomainDumpXML, /* domainDumpXML */
    lxcListDefinedDomains, /* listDefinedDomains */
    lxcNumDefinedDomains, /* numOfDefinedDomains */
    lxcDomainStart, /* domainCreate */
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
    NULL, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    NULL, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
};


static virStateDriver lxcStateDriver = {
    lxcStartup,
    lxcShutdown,
    NULL, /* reload */
    lxcActive,
    NULL,
};

int lxcRegister(void)
{
    virRegisterDriver(&lxcDriver);
    virRegisterStateDriver(&lxcStateDriver);
    return 0;
}

#endif /* WITH_LXC */
