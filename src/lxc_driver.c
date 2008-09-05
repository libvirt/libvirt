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

#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_driver.h"
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
    virDomainObjPtr vm = virDomainFindByID(driver->domains, id);
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
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, uuid);
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
    virDomainObjPtr vm = virDomainFindByName(driver->domains, name);
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

static int lxcListDomains(virConnectPtr conn, int *ids, int nids) {
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    virDomainObjPtr vm = driver->domains;
    int got = 0;
    while (vm && got < nids) {
        if (virDomainIsActive(vm)) {
            ids[got] = vm->def->id;
            got++;
        }
        vm = vm->next;
    }
    return got;
}
static int lxcNumDomains(virConnectPtr conn) {
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    int n = 0;
    virDomainObjPtr dom = driver->domains;
    while (dom) {
        if (virDomainIsActive(dom))
            n++;
        dom = dom->next;
    }
    return n;
}

static int lxcListDefinedDomains(virConnectPtr conn,
                                 char **const names, int nnames) {
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    virDomainObjPtr vm = driver->domains;
    int got = 0, i;
    while (vm && got < nnames) {
        if (!virDomainIsActive(vm)) {
            if (!(names[got] = strdup(vm->def->name))) {
                lxcError(conn, NULL, VIR_ERR_NO_MEMORY, NULL);
                goto cleanup;
            }
            got++;
        }
        vm = vm->next;
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}


static int lxcNumDefinedDomains(virConnectPtr conn) {
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    int n = 0;
    virDomainObjPtr dom = driver->domains;
    while (dom) {
        if (!virDomainIsActive(dom))
            n++;
        dom = dom->next;
    }
    return n;
}



static virDomainPtr lxcDomainDefine(virConnectPtr conn, const char *xml)
{
    lxc_driver_t *driver = (lxc_driver_t *)conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm;
    virDomainPtr dom;

    if (!(def = virDomainDefParseString(conn, driver->caps, xml)))
        return NULL;

    if ((def->nets != NULL) && !(driver->have_netns)) {
        lxcError(conn, NULL, VIR_ERR_NO_SUPPORT,
                 _("System lacks NETNS support"));
        virDomainDefFree(def);
        return NULL;
    }

    if (!(vm = virDomainAssignDef(conn, &driver->domains, def))) {
        virDomainDefFree(def);
        return NULL;
    }
    vm->persistent = 1;

    if (virDomainSaveConfig(conn,
                            driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains, vm);
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
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with matching uuid"));
        return -1;
    }

    if (virDomainIsActive(vm)) {
        lxcError(dom->conn, dom, VIR_ERR_INTERNAL_ERROR,
                 _("cannot delete active domain"));
        return -1;
    }

    if (!vm->persistent) {
        lxcError(dom->conn, dom, VIR_ERR_INTERNAL_ERROR,
                 "%s", _("cannot undefine transient domain"));
        return -1;
    }

    if (virDomainDeleteConfig(dom->conn,
                              driver->configDir,
                              driver->autostartDir,
                              vm) <0)
        return -1;

    virDomainRemoveInactive(&driver->domains, vm);

    return 0;
}

static int lxcDomainGetInfo(virDomainPtr dom,
                            virDomainInfoPtr info)
{
    lxc_driver_t *driver = (lxc_driver_t *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with matching uuid"));
        return -1;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        info->cpuTime = 0;
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = 1;

    return 0;
}

static char *lxcGetOSType(virDomainPtr dom)
{
    lxc_driver_t *driver = (lxc_driver_t *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with matching uuid"));
        return NULL;
    }

    return strdup(vm->def->os.type);
}

static char *lxcDomainDumpXML(virDomainPtr dom,
                              int flags)
{
    lxc_driver_t *driver = (lxc_driver_t *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        lxcError(dom->conn, dom, VIR_ERR_INVALID_DOMAIN,
                 _("no domain with matching uuid"));
        return NULL;
    }

    return virDomainDefFormat(dom->conn,
                              (flags & VIR_DOMAIN_XML_INACTIVE) &&
                              vm->newDef ? vm->newDef : vm->def,
                              flags);
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
    virDomainNetDefPtr net;

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
    virDomainDeleteConfig(conn, driver->stateDir, NULL, vm);

    vm->state = VIR_DOMAIN_SHUTOFF;
    vm->pid = -1;
    vm->def->id = -1;
    vm->monitor = -1;

    for (net = vm->def->nets; net; net = net->next) {
        vethInterfaceUpOrDown(net->ifname, 0);
        vethDelete(net->ifname);
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
    int rc = -1;
    virDomainNetDefPtr net;
    char *bridge = NULL;
    char parentVeth[PATH_MAX] = "";
    char containerVeth[PATH_MAX] = "";
    brControl *brctl = NULL;

    if (brInit(&brctl) != 0)
        return -1;

    for (net = def->nets; net; net = net->next) {
        switch (net->type) {
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        {
            virNetworkPtr network = virNetworkLookupByName(conn,
                                                           net->data.network.name);
            if (!network) {
                goto error_exit;
            }

            bridge = virNetworkGetBridgeName(network);

            virNetworkFree(network);
            break;
        }
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            bridge = net->data.bridge.brname;
            break;
        }

        DEBUG("bridge: %s", bridge);
        if (NULL == bridge) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to get bridge for interface"));
            goto error_exit;
        }

        DEBUG0("calling vethCreate()");
        if (NULL != net->ifname) {
            strcpy(parentVeth, net->ifname);
        }
        DEBUG("parentVeth: %s, containerVeth: %s", parentVeth, containerVeth);
        if (0 != (rc = vethCreate(parentVeth, PATH_MAX, containerVeth, PATH_MAX))) {
            lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to create veth device pair: %d"), rc);
            goto error_exit;
        }
        if (NULL == net->ifname) {
            net->ifname = strdup(parentVeth);
        }
        if (VIR_REALLOC_N(*veths, (*nveths)+1) < 0)
            goto error_exit;
        if (((*veths)[(*nveths)++] = strdup(containerVeth)) == NULL)
            goto error_exit;

        if (NULL == net->ifname) {
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


static int lxcMonitorClient(virConnectPtr conn,
                            lxc_driver_t * driver,
                            virDomainObjPtr vm)
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
    virDomainObjPtr vm = driver->domains;

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
    lxc_driver_t *driver = conn->privateData;

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
    if (!emulator)
        emulator = virDomainDefDefaultEmulator(conn, vm->def, driver->caps);
    if (!emulator)
        return -1;

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

    vm->stdin_fd = -1;
    vm->stdout_fd = vm->stderr_fd = logfd;

    FD_SET(appPty, &keepfd);

    if (virExec(conn, largv, NULL, &keepfd, &child,
                vm->stdin_fd, &vm->stdout_fd, &vm->stderr_fd,
                VIR_EXEC_NONE) < 0)
        goto cleanup;

    /* We now wait for the process to exit - the controller
     * will fork() itself into the background - waiting for
     * it to exit thus guarentees it has written its pidfile
     */
    while ((rc = waitpid(child, &status, 0) == -1) && errno == EINTR);
    if (rc == -1) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("cannot wait for '%s': %s"),
                 largv[0], strerror(errno));
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
    lxcError(conn, NULL, VIR_ERR_NO_MEMORY, NULL);
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

    /* open parent tty */
    if (virFileOpenTty(&parentTty, &parentTtyPath, 1) < 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to allocate tty: %s"),
                 strerror(errno));
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
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to open %s: %s"), logfile,
                 strerror(errno));
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
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Failed to read pid file %s/%s.pid: %s"),
                 driver->stateDir, vm->def->name, strerror(rc));
        rc = -1;
        goto cleanup;
    }

    vm->def->id = vm->pid;
    vm->state = VIR_DOMAIN_RUNNING;

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
    virDomainObjPtr vm = virDomainFindByName(driver->domains, dom->name);

    if (!vm) {
        lxcError(conn, dom, VIR_ERR_INVALID_DOMAIN,
                 "no domain with uuid");
        goto cleanup;
    }

    if ((vm->def->nets != NULL) && !(driver->have_netns)) {
        lxcError(conn, NULL, VIR_ERR_NO_SUPPORT,
                 _("System lacks NETNS support"));
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
    virDomainObjPtr vm;
    virDomainDefPtr def;
    virDomainPtr dom = NULL;

    if (!(def = virDomainDefParseString(conn, driver->caps, xml)))
        goto return_point;

    if ((def->nets != NULL) && !(driver->have_netns)) {
        virDomainDefFree(def);
        lxcError(conn, NULL, VIR_ERR_NO_SUPPORT,
                 _("System lacks NETNS support"));
        goto return_point;
    }


    if (!(vm = virDomainAssignDef(conn, &driver->domains, def))) {
        virDomainDefFree(def);
        goto return_point;
    }

    if (lxcVmStart(conn, driver, vm) < 0) {
        virDomainRemoveInactive(&driver->domains, vm);
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
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);

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
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);

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
    virDomainObjPtr vm;

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

    if ((lxc_driver->caps = lxcCapsInit()) == NULL) {
        lxcShutdown();
        return -1;
    }

    if (virDomainLoadAllConfigs(NULL,
                                lxc_driver->caps,
                                &lxc_driver->domains,
                                lxc_driver->configDir,
                                lxc_driver->autostartDir) < 0) {
        lxcShutdown();
        return -1;
    }

    vm = lxc_driver->domains;
    while (vm) {
        char *config = NULL;
        virDomainDefPtr tmp;
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

        if ((config = virDomainConfigFile(NULL,
                                          lxc_driver->stateDir,
                                          vm->def->name)) == NULL)
            continue;

        /* Try and load the live config */
        tmp = virDomainDefParseFile(NULL, lxc_driver->caps, config);
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

        vm = vm->next;
    }

    return 0;
}

static void lxcFreeDriver(lxc_driver_t *driver)
{
    VIR_FREE(driver->configDir);
    VIR_FREE(driver->autostartDir);
    VIR_FREE(driver->stateDir);
    VIR_FREE(driver->logDir);
    VIR_FREE(driver);
}

static int lxcShutdown(void)
{
    virDomainObjPtr vm;
    if (lxc_driver == NULL)
        return(-1);
    vm = lxc_driver->domains;
    while (vm) {
        virDomainObjPtr next = vm->next;
        virDomainObjFree(vm);
        vm = next;
    }
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
    virDomainObjPtr dom;

    if (lxc_driver == NULL)
        return(0);

    dom = lxc_driver->domains;
    while (dom) {
        if (virDomainIsActive(dom))
            return 1;
        dom = dom->next;
    }

    /* Otherwise we're happy to deal with a shutdown */
    return 0;
}

static int lxcVersion(virConnectPtr conn, unsigned long *version)
{
    struct utsname ver;
    int maj;
    int min;
    int rev;

    if (uname(&ver) != 0) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("uname(): %m"));
        return -1;
    }

    if (sscanf(ver.release, "%i.%i.%i", &maj, &min, &rev) != 3) {
        lxcError(conn, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Unknown release: %s"), ver.release);
        return -1;
    }

    *version = (maj * 1000 * 1000) + (min * 1000) + rev;

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
    lxcVersion, /* version */
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
