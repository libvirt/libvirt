/*
 * driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006, 2007, 2008, 2009 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
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
#include <sys/ioctl.h>

#if HAVE_NUMACTL
#define NUMA_VERSION1_COMPATIBILITY 1
#include <numa.h>
#endif

#if HAVE_SCHED_H
#include <sched.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "qemu_driver.h"
#include "qemu_conf.h"
#include "c-ctype.h"
#include "event.h"
#include "buf.h"
#include "util.h"
#include "nodeinfo.h"
#include "stats_linux.h"
#include "capabilities.h"
#include "memory.h"
#include "uuid.h"
#include "domain_conf.h"
#include "node_device_conf.h"
#include "pci.h"
#include "security.h"


#define VIR_FROM_THIS VIR_FROM_QEMU

/* For storing short-lived temporary files. */
#define TEMPDIR LOCAL_STATE_DIR "/cache/libvirt"

#define QEMU_CMD_PROMPT "\n(qemu) "
#define QEMU_PASSWD_PROMPT "Password: "


static int qemudShutdown(void);

static void qemuDriverLock(struct qemud_driver *driver)
{
    virMutexLock(&driver->lock);
}
static void qemuDriverUnlock(struct qemud_driver *driver)
{
    virMutexUnlock(&driver->lock);
}

static void qemuDomainEventFlush(int timer, void *opaque);
static void qemuDomainEventQueue(struct qemud_driver *driver,
                                 virDomainEventPtr event);

static void qemudDispatchVMEvent(int watch,
                                 int fd,
                                 int events,
                                 void *opaque);

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom,
                              int stdin_fd);

static void qemudShutdownVMDaemon(virConnectPtr conn,
                                  struct qemud_driver *driver,
                                  virDomainObjPtr vm);

static int qemudDomainGetMaxVcpus(virDomainPtr dom);

static int qemudMonitorCommand(const virDomainObjPtr vm,
                               const char *cmd,
                               char **reply);
static int qemudMonitorCommandExtra(const virDomainObjPtr vm,
                                    const char *cmd,
                                    const char *extra,
                                    const char *extraPrompt,
                                    char **reply);

static struct qemud_driver *qemu_driver = NULL;


static int
qemudLogFD(virConnectPtr conn, const char* logDir, const char* name)
{
    char logfile[PATH_MAX];
    mode_t logmode;
    uid_t uid = geteuid();
    int ret, fd = -1;

    if ((ret = snprintf(logfile, sizeof(logfile), "%s/%s.log", logDir, name))
        < 0 || ret >= sizeof(logfile)) {
        virReportOOMError(conn);
        return -1;
    }

    logmode = O_CREAT | O_WRONLY;
    if (uid != 0)
        logmode |= O_TRUNC;
    else
        logmode |= O_APPEND;
    if ((fd = open(logfile, logmode, S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(conn, errno,
                             _("failed to create logfile %s"),
                             logfile);
        return -1;
    }
    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(conn, errno, "%s",
                             _("Unable to set VM logfile close-on-exec flag"));
        close(fd);
        return -1;
    }
    return fd;
}


static int
qemudLogReadFD(virConnectPtr conn, const char* logDir, const char* name, off_t pos)
{
    char logfile[PATH_MAX];
    mode_t logmode = O_RDONLY;
    int ret, fd = -1;

    if ((ret = snprintf(logfile, sizeof(logfile), "%s/%s.log", logDir, name))
        < 0 || ret >= sizeof(logfile)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to build logfile name %s/%s.log"),
                         logDir, name);
        return -1;
    }


    if ((fd = open(logfile, logmode)) < 0) {
        virReportSystemError(conn, errno,
                             _("failed to create logfile %s"),
                             logfile);
        return -1;
    }
    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(conn, errno, "%s",
                             _("Unable to set VM logfile close-on-exec flag"));
        close(fd);
        return -1;
    }
    if (lseek(fd, pos, SEEK_SET) < 0) {
        virReportSystemError(conn, errno,
                             _("Unable to seek to %lld in %s"),
                             (long long) pos, logfile);
        close(fd);
    }
    return fd;
}


static void
qemudAutostartConfigs(struct qemud_driver *driver) {
    unsigned int i;
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen(getuid() ?
                                        "qemu:///session" :
                                        "qemu:///system");
    /* Ignoring NULL conn which is mostly harmless here */

    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjPtr vm = driver->domains.objs[i];
        virDomainObjLock(vm);
        if (vm->autostart &&
            !virDomainIsActive(vm)) {
            int ret = qemudStartVMDaemon(conn, driver, vm, NULL, -1);
            if (ret < 0) {
                virErrorPtr err = virGetLastError();
                VIR_ERROR(_("Failed to autostart VM '%s': %s\n"),
                          vm->def->name,
                          err ? err->message : NULL);
            } else {
                virDomainEventPtr event =
                    virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STARTED,
                                             VIR_DOMAIN_EVENT_STARTED_BOOTED);
                if (event)
                    qemuDomainEventQueue(driver, event);
            }
        }
        virDomainObjUnlock(vm);
    }

    virConnectClose(conn);
}


/**
 * qemudRemoveDomainStatus
 *
 * remove all state files of a domain from statedir
 *
 * Returns 0 on success
 */
static int
qemudRemoveDomainStatus(virConnectPtr conn,
                        struct qemud_driver *driver,
                        virDomainObjPtr vm)
{
    int rc = -1;
    char *file = NULL;

    if (virAsprintf(&file, "%s/%s.xml", driver->stateDir, vm->def->name) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR) {
        qemudReportError(conn, vm, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Failed to unlink status file %s"), file);
        goto cleanup;
    }

    if(virFileDeletePid(driver->stateDir, vm->def->name))
        goto cleanup;

    rc = 0;
cleanup:
    VIR_FREE(file);
    return rc;
}


static int qemudOpenMonitor(virConnectPtr conn,
                            struct qemud_driver* driver,
                            virDomainObjPtr vm,
                            const char *monitor,
                            int reconnect);

/**
 * qemudReconnectVMs
 *
 * Reconnect running vms to the daemon process
 */
static int
qemudReconnectVMs(struct qemud_driver *driver)
{
    int i;

    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjPtr vm = driver->domains.objs[i];
        qemudDomainStatusPtr status = NULL;
        char *config = NULL;
        int rc;

        virDomainObjLock(vm);
        if ((rc = virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) == 0)
            DEBUG("Found pid %d for '%s'", vm->pid, vm->def->name);
        else
            goto next;

        if ((config = virDomainConfigFile(NULL,
                                          driver->stateDir,
                                          vm->def->name)) == NULL) {
            VIR_ERROR(_("Failed to read domain status for %s\n"),
                      vm->def->name);
            goto next_error;
        }

        status = qemudDomainStatusParseFile(NULL, driver->caps, config, 0);
        if (status) {
            vm->newDef = vm->def;
            vm->def = status->def;
        } else {
            VIR_ERROR(_("Failed to parse domain status for %s\n"),
                      vm->def->name);
            goto next_error;
        }

        if ((rc = qemudOpenMonitor(NULL, driver, vm, status->monitorpath, 1)) != 0) {
            VIR_ERROR(_("Failed to reconnect monitor for %s: %d\n"),
                      vm->def->name, rc);
            goto next_error;
        }

        if ((vm->logfile = qemudLogFD(NULL, driver->logDir, vm->def->name)) < 0)
            return -1;

        if (vm->def->id >= driver->nextvmid)
            driver->nextvmid = vm->def->id + 1;

        vm->state = status->state;
        goto next;

next_error:
        /* we failed to reconnect the vm so remove it's traces */
        vm->def->id = -1;
        qemudRemoveDomainStatus(NULL, driver, vm);
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->newDef = NULL;
next:
        virDomainObjUnlock(vm);
        if (status)
            VIR_FREE(status->monitorpath);
        VIR_FREE(status);
        VIR_FREE(config);
    }
    return 0;
}

static int
qemudSecurityInit(struct qemud_driver *qemud_drv)
{
    int ret;
    const char *doi, *model;
    virCapsPtr caps;
    virSecurityDriverPtr security_drv;

    ret = virSecurityDriverStartup(&security_drv,
                                   qemud_drv->securityDriverName);
    if (ret == -1) {
        VIR_ERROR0(_("Failed to start security driver"));
        return -1;
    }
    /* No security driver wanted to be enabled: just return */
    if (ret == -2) {
        VIR_INFO0(_("No security driver available"));
        return 0;
    }

    qemud_drv->securityDriver = security_drv;
    doi = virSecurityDriverGetDOI(security_drv);
    model = virSecurityDriverGetModel(security_drv);

    VIR_DEBUG("Initialized security driver \"%s\" with "
              "DOI \"%s\"", model, doi);

    /*
     * Add security policy host caps now that the security driver is
     * initialized.
     */
    caps = qemud_drv->caps;

    caps->host.secModel.model = strdup(model);
    if (!caps->host.secModel.model) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to copy secModel model: %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        return -1;
    }

    caps->host.secModel.doi = strdup(doi);
    if (!caps->host.secModel.doi) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to copy secModel DOI: %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        return -1;
    }

    return 0;
}

/**
 * qemudStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
qemudStartup(void) {
    uid_t uid = geteuid();
    char *base = NULL;
    char driverConf[PATH_MAX];

    if (VIR_ALLOC(qemu_driver) < 0)
        return -1;

    if (virMutexInit(&qemu_driver->lock) < 0) {
        VIR_ERROR("%s", _("cannot initialize mutex"));
        VIR_FREE(qemu_driver);
        return -1;
    }
    qemuDriverLock(qemu_driver);

    /* Don't have a dom0 so start from 1 */
    qemu_driver->nextvmid = 1;

    /* Init callback list */
    if(VIR_ALLOC(qemu_driver->domainEventCallbacks) < 0)
        goto out_of_memory;
    if (!(qemu_driver->domainEventQueue = virDomainEventQueueNew()))
        goto out_of_memory;

    if ((qemu_driver->domainEventTimer =
         virEventAddTimeout(-1, qemuDomainEventFlush, qemu_driver, NULL)) < 0)
        goto error;

    if (!uid) {
        if (virAsprintf(&qemu_driver->logDir,
                        "%s/log/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;

        if (virAsprintf(&qemu_driver->stateDir,
                      "%s/run/libvirt/qemu/", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;
    } else {
        char *userdir = virGetUserDirectory(NULL, uid);
        if (!userdir)
            goto error;

        if (virAsprintf(&qemu_driver->logDir,
                        "%s/.libvirt/qemu/log", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }

        if (virAsprintf(&base, "%s/.libvirt", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }
        VIR_FREE(userdir);

        if (virAsprintf(&qemu_driver->stateDir, "%s/qemu/run", base) == -1)
            goto out_of_memory;
    }

    if (virFileMakePath(qemu_driver->stateDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create state dir '%s': %s\n"),
                  qemu_driver->stateDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }

    /* Configuration paths are either ~/.libvirt/qemu/... (session) or
     * /etc/libvirt/qemu/... (system).
     */
    if (snprintf (driverConf, sizeof(driverConf), "%s/qemu.conf", base) == -1)
        goto out_of_memory;
    driverConf[sizeof(driverConf)-1] = '\0';

    if (virAsprintf(&qemu_driver->configDir, "%s/qemu", base) == -1)
        goto out_of_memory;

    if (virAsprintf(&qemu_driver->autostartDir, "%s/qemu/autostart", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if ((qemu_driver->caps = qemudCapsInit()) == NULL)
        goto out_of_memory;

    if (qemudSecurityInit(qemu_driver) < 0) {
        goto error;
    }

    if (qemudLoadDriverConfig(qemu_driver, driverConf) < 0) {
        goto error;
    }

    if (virDomainLoadAllConfigs(NULL,
                                qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->configDir,
                                qemu_driver->autostartDir,
                                NULL, NULL) < 0)
        goto error;
    qemudReconnectVMs(qemu_driver);
    qemudAutostartConfigs(qemu_driver);

    qemuDriverUnlock(qemu_driver);

    return 0;

out_of_memory:
    virReportOOMError(NULL);
error:
    if (qemu_driver)
        qemuDriverUnlock(qemu_driver);
    VIR_FREE(base);
    qemudShutdown();
    return -1;
}

static void qemudNotifyLoadDomain(virDomainObjPtr vm, int newVM, void *opaque)
{
    struct qemud_driver *driver = opaque;

    if (newVM) {
        virDomainEventPtr event =
            virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
        if (event)
            qemuDomainEventQueue(driver, event);
    }
}

/**
 * qemudReload:
 *
 * Function to restart the QEmu daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
qemudReload(void) {
    if (!qemu_driver)
        return 0;

    qemuDriverLock(qemu_driver);
    virDomainLoadAllConfigs(NULL,
                            qemu_driver->caps,
                            &qemu_driver->domains,
                            qemu_driver->configDir,
                            qemu_driver->autostartDir,
                            qemudNotifyLoadDomain, qemu_driver);

    qemudAutostartConfigs(qemu_driver);
    qemuDriverUnlock(qemu_driver);

    return 0;
}

/**
 * qemudActive:
 *
 * Checks if the QEmu daemon is active, i.e. has an active domain or
 * an active network
 *
 * Returns 1 if active, 0 otherwise
 */
static int
qemudActive(void) {
    unsigned int i;
    int active = 0;

    if (!qemu_driver)
        return 0;

    qemuDriverLock(qemu_driver);
    for (i = 0 ; i < qemu_driver->domains.count ; i++) {
        virDomainObjPtr vm = qemu_driver->domains.objs[i];
        virDomainObjLock(vm);
        if (virDomainIsActive(vm))
            active = 1;
        virDomainObjUnlock(vm);
    }

    qemuDriverUnlock(qemu_driver);
    return active;
}

/**
 * qemudShutdown:
 *
 * Shutdown the QEmu daemon, it will stop all active domains and networks
 */
static int
qemudShutdown(void) {

    if (!qemu_driver)
        return -1;

    qemuDriverLock(qemu_driver);
    virCapabilitiesFree(qemu_driver->caps);

    virDomainObjListFree(&qemu_driver->domains);

    VIR_FREE(qemu_driver->securityDriverName);
    VIR_FREE(qemu_driver->logDir);
    VIR_FREE(qemu_driver->configDir);
    VIR_FREE(qemu_driver->autostartDir);
    VIR_FREE(qemu_driver->stateDir);
    VIR_FREE(qemu_driver->vncTLSx509certdir);
    VIR_FREE(qemu_driver->vncListen);
    VIR_FREE(qemu_driver->vncPassword);

    /* Free domain callback list */
    virDomainEventCallbackListFree(qemu_driver->domainEventCallbacks);
    virDomainEventQueueFree(qemu_driver->domainEventQueue);

    if (qemu_driver->domainEventTimer != -1)
        virEventRemoveTimeout(qemu_driver->domainEventTimer);

    if (qemu_driver->brctl)
        brShutdown(qemu_driver->brctl);

    qemuDriverUnlock(qemu_driver);
    virMutexDestroy(&qemu_driver->lock);
    VIR_FREE(qemu_driver);

    return 0;
}

/* Return -1 for error, 1 to continue reading and 0 for success */
typedef int qemudHandlerMonitorOutput(virConnectPtr conn,
                                      virDomainObjPtr vm,
                                      const char *output,
                                      int fd);

/*
 * Returns -1 for error, 0 on end-of-file, 1 for success
 */
static int
qemudReadMonitorOutput(virConnectPtr conn,
                       virDomainObjPtr vm,
                       int fd,
                       char *buf,
                       size_t buflen,
                       qemudHandlerMonitorOutput func,
                       const char *what,
                       int timeout)
{
    size_t got = 0;
    buf[0] = '\0';
    timeout *= 1000; /* poll wants milli seconds */

    /* Consume & discard the initial greeting */
    while (got < (buflen-1)) {
        ssize_t ret;

        ret = read(fd, buf+got, buflen-got-1);

        if (ret < 0) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (errno == EINTR)
                continue;

            if (errno != EAGAIN) {
                virReportSystemError(conn, errno,
                                     _("Failure while reading %s startup output"),
                                     what);
                return -1;
            }

            ret = poll(&pfd, 1, timeout);
            if (ret == 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Timed out while reading %s startup output"), what);
                return -1;
            } else if (ret == -1) {
                if (errno != EINTR) {
                    virReportSystemError(conn, errno,
                                         _("Failure while reading %s startup output"),
                                         what);
                    return -1;
                }
            } else {
                /* Make sure we continue loop & read any further data
                   available before dealing with EOF */
                if (pfd.revents & (POLLIN | POLLHUP))
                    continue;

                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Failure while reading %s startup output"), what);
                return -1;
            }
        } else if (ret == 0) {
            return 0;
        } else {
            got += ret;
            buf[got] = '\0';
            ret = func(conn, vm, buf, fd);
            if (ret == -1)
                return -1;
            if (ret == 1)
                continue;
            return 1;
        }
    }

    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("Out of space while reading %s startup output"), what);
    return -1;

}


/*
 * Returns -1 for error, 0 on success
 */
static int
qemudReadLogOutput(virConnectPtr conn,
                   virDomainObjPtr vm,
                   int fd,
                   char *buf,
                   size_t buflen,
                   qemudHandlerMonitorOutput func,
                   const char *what,
                   int timeout)
{
    int retries = timeout*10;
    buf[0] = '\0';

    while (retries) {
        ssize_t ret;
        size_t got = 0;

        while((ret = read(fd, buf+got, buflen-got-1)) > 0) {
            got += ret;
            buf[got] = '\0';
            if ((buflen-got-1) == 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Out of space while reading %s log output"), what);
                return -1;
            }
        }

        if (ret < 0 && errno != EINTR) {
            virReportSystemError(conn, errno,
                                 _("Failure while reading %s log output"),
                                 what);
            return -1;
        }

        ret = func(conn, vm, buf, fd);
        if (ret <= 0)
            return ret;

        usleep(100*1000);
        retries--;
    }
    if (retries == 0)
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Timed out while reading %s log output"), what);
    return -1;
}

static int
qemudCheckMonitorPrompt(virConnectPtr conn ATTRIBUTE_UNUSED,
                        virDomainObjPtr vm,
                        const char *output,
                        int fd)
{
    if (strstr(output, "(qemu) ") == NULL)
        return 1; /* keep reading */

    vm->monitor = fd;

    return 0;
}

static int qemudOpenMonitor(virConnectPtr conn,
                            struct qemud_driver* driver,
                            virDomainObjPtr vm,
                            const char *monitor,
                            int reconnect) {
    int monfd;
    char buf[1024];
    int ret = -1;

    if ((monfd = open(monitor, O_RDWR)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unable to open monitor path %s"), monitor);
        return -1;
    }
    if (virSetCloseExec(monfd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to set monitor close-on-exec flag"));
        goto error;
    }
    if (virSetNonBlock(monfd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to put monitor into non-blocking mode"));
        goto error;
    }

    if (!reconnect) {
        if (qemudReadMonitorOutput(conn,
                                   vm, monfd,
                                   buf, sizeof(buf),
                                   qemudCheckMonitorPrompt,
                                   "monitor", 10) <= 0)
            ret = -1;
        else
            ret = 0;
    } else {
        vm->monitor = monfd;
        ret = 0;
    }

    if (ret != 0)
         goto error;

    if (!(vm->monitorpath = strdup(monitor))) {
        virReportOOMError(conn);
        goto error;
    }

    if ((vm->monitorWatch = virEventAddHandle(vm->monitor, 0,
                                              qemudDispatchVMEvent,
                                              driver, NULL)) < 0)
        goto error;


    /* Keep monitor open upon success */
    if (ret == 0)
        return ret;

 error:
    close(monfd);
    return ret;
}

/* Returns -1 for error, 0 success, 1 continue reading */
static int qemudExtractMonitorPath(virConnectPtr conn,
                                   const char *haystack,
                                   size_t *offset,
                                   char **path) {
    static const char needle[] = "char device redirected to";
    char *tmp, *dev;

    VIR_FREE(*path);
    /* First look for our magic string */
    if (!(tmp = strstr(haystack + *offset, needle))) {
        return 1;
    }
    tmp += sizeof(needle);
    dev = tmp;

    /*
     * And look for first whitespace character and nul terminate
     * to mark end of the pty path
     */
    while (*tmp) {
        if (c_isspace(*tmp)) {
            if (VIR_ALLOC_N(*path, (tmp-dev)+1) < 0) {
                virReportOOMError(conn);
                return -1;
            }
            strncpy(*path, dev, (tmp-dev));
            (*path)[(tmp-dev)] = '\0';
            /* ... now further update offset till we get EOL */
            *offset = tmp - haystack;
            return 0;
        }
        tmp++;
    }

    /*
     * We found a path, but didn't find any whitespace,
     * so it must be still incomplete - we should at
     * least see a \n - indicate that we want to carry
     * on trying again
     */
    return 1;
}

static int
qemudFindCharDevicePTYs(virConnectPtr conn,
                        virDomainObjPtr vm,
                        const char *output,
                        int fd ATTRIBUTE_UNUSED)
{
    struct qemud_driver* driver = conn->privateData;
    char *monitor = NULL;
    size_t offset = 0;
    int ret, i;

    /* The order in which QEMU prints out the PTY paths is
       the order in which it procsses its monitor, serial
       and parallel device args. This code must match that
       ordering.... */

    /* So first comes the monitor device */
    if ((ret = qemudExtractMonitorPath(conn, output, &offset, &monitor)) != 0)
        goto cleanup;

    /* then the serial devices */
    for (i = 0 ; i < vm->def->nserials ; i++) {
        virDomainChrDefPtr chr = vm->def->serials[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                goto cleanup;
        }
    }

    /* and finally the parallel devices */
    for (i = 0 ; i < vm->def->nparallels ; i++) {
        virDomainChrDefPtr chr = vm->def->parallels[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                goto cleanup;
        }
    }

    /* Got them all, so now open the monitor console */
    ret = qemudOpenMonitor(conn, driver, vm, monitor, 0);

cleanup:
    VIR_FREE(monitor);
    return ret;
}

static int qemudWaitForMonitor(virConnectPtr conn,
                               struct qemud_driver* driver,
                               virDomainObjPtr vm, off_t pos)
{
    char buf[1024]; /* Plenty of space to get startup greeting */
    int logfd;
    int ret;

    if ((logfd = qemudLogReadFD(conn, driver->logDir, vm->def->name, pos))
        < 0)
        return -1;

    ret = qemudReadLogOutput(conn, vm, logfd, buf, sizeof(buf),
                             qemudFindCharDevicePTYs,
                             "console", 3);
    if (close(logfd) < 0) {
        char ebuf[1024];
        VIR_WARN(_("Unable to close logfile: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    if (ret == 0) /* success */
        return 0;

    /* Unexpected end of file - inform user of QEMU log data */
    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("unable to start guest: %s"), buf);
    return -1;
}

static int
qemudDetectVcpuPIDs(virConnectPtr conn,
                    virDomainObjPtr vm) {
    char *qemucpus = NULL;
    char *line;
    int lastVcpu = -1;

    /* Only KVM has seperate threads for CPUs,
       others just use main QEMU process for CPU */
    if (vm->def->virtType != VIR_DOMAIN_VIRT_KVM)
        vm->nvcpupids = 1;
    else
        vm->nvcpupids = vm->def->vcpus;

    if (VIR_ALLOC_N(vm->vcpupids, vm->nvcpupids) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    if (vm->def->virtType != VIR_DOMAIN_VIRT_KVM) {
        vm->vcpupids[0] = vm->pid;
        return 0;
    }

    if (qemudMonitorCommand(vm, "info cpus", &qemucpus) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot run monitor command to fetch CPU thread info"));
        VIR_FREE(vm->vcpupids);
        vm->nvcpupids = 0;
        return -1;
    }

    /*
     * This is the gross format we're about to parse :-{
     *
     * (qemu) info cpus
     * * CPU #0: pc=0x00000000000f0c4a thread_id=30019
     *   CPU #1: pc=0x00000000fffffff0 thread_id=30020
     *   CPU #2: pc=0x00000000fffffff0 thread_id=30021
     *
     */
    line = qemucpus;
    do {
        char *offset = strchr(line, '#');
        char *end = NULL;
        int vcpu = 0, tid = 0;

        /* See if we're all done */
        if (offset == NULL)
            break;

        /* Extract VCPU number */
        if (virStrToLong_i(offset + 1, &end, 10, &vcpu) < 0)
            goto error;
        if (end == NULL || *end != ':')
            goto error;

        /* Extract host Thread ID */
        if ((offset = strstr(line, "thread_id=")) == NULL)
            goto error;
        if (virStrToLong_i(offset + strlen("thread_id="), &end, 10, &tid) < 0)
            goto error;
        if (end == NULL || !c_isspace(*end))
            goto error;

        /* Validate the VCPU is in expected range & order */
        if (vcpu > vm->nvcpupids ||
            vcpu != (lastVcpu + 1))
            goto error;

        lastVcpu = vcpu;
        vm->vcpupids[vcpu] = tid;

        /* Skip to next data line */
        line = strchr(offset, '\r');
        if (line == NULL)
            line = strchr(offset, '\n');
    } while (line != NULL);

    /* Validate we got data for all VCPUs we expected */
    if (lastVcpu != (vm->def->vcpus - 1))
        goto error;

    VIR_FREE(qemucpus);
    return 0;

error:
    VIR_FREE(vm->vcpupids);
    vm->nvcpupids = 0;
    VIR_FREE(qemucpus);

    /* Explicitly return success, not error. Older KVM does
       not have vCPU -> Thread mapping info and we don't
       want to break its use. This merely disables ability
       to pin vCPUS with libvirt */
    return 0;
}

static int
qemudInitCpus(virConnectPtr conn,
              virDomainObjPtr vm,
              const char *migrateFrom) {
    char *info = NULL;
#if HAVE_SCHED_GETAFFINITY
    cpu_set_t mask;
    int i, maxcpu = QEMUD_CPUMASK_LEN;
    virNodeInfo nodeinfo;

    if (virNodeInfoPopulate(conn, &nodeinfo) < 0)
        return -1;

    /* setaffinity fails if you set bits for CPUs which
     * aren't present, so we have to limit ourselves */
    if (maxcpu > nodeinfo.cpus)
        maxcpu = nodeinfo.cpus;

    CPU_ZERO(&mask);
    if (vm->def->cpumask) {
        for (i = 0 ; i < maxcpu ; i++)
            if (vm->def->cpumask[i])
                CPU_SET(i, &mask);
    } else {
        for (i = 0 ; i < maxcpu ; i++)
            CPU_SET(i, &mask);
    }

    for (i = 0 ; i < vm->nvcpupids ; i++) {
        if (sched_setaffinity(vm->vcpupids[i],
                              sizeof(mask), &mask) < 0) {
            virReportSystemError(conn, errno, "%s",
                                 _("failed to set CPU affinity"));
            return -1;
        }
    }
#endif /* HAVE_SCHED_GETAFFINITY */

    if (migrateFrom == NULL) {
        /* Allow the CPUS to start executing */
        if (qemudMonitorCommand(vm, "cont", &info) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("resume operation failed"));
            return -1;
        }
        VIR_FREE(info);
    }

    return 0;
}


static int
qemudInitPasswords(virConnectPtr conn,
                   struct qemud_driver *driver,
                   virDomainObjPtr vm) {
    char *info = NULL;

    /*
     * NB: Might have more passwords to set in the future. eg a qcow
     * disk decryption password, but there's no monitor command
     * for that yet...
     */

    if (vm->def->graphics &&
        vm->def->graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        (vm->def->graphics->data.vnc.passwd || driver->vncPassword)) {

        if (qemudMonitorCommandExtra(vm, "change vnc password",
                                     vm->def->graphics->data.vnc.passwd ?
                                     vm->def->graphics->data.vnc.passwd :
                                     driver->vncPassword,
                                     QEMU_PASSWD_PROMPT,
                                     &info) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("setting VNC password failed"));
            return -1;
        }
        VIR_FREE(info);
    }

    return 0;
}


static int qemudNextFreeVNCPort(struct qemud_driver *driver ATTRIBUTE_UNUSED) {
    int i;

    for (i = 5900 ; i < 6000 ; i++) {
        int fd;
        int reuse = 1;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(i);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse, sizeof(reuse)) < 0) {
            close(fd);
            break;
        }

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            /* Not in use, lets grab it */
            close(fd);
            return i;
        }
        close(fd);

        if (errno == EADDRINUSE) {
            /* In use, try next */
            continue;
        }
        /* Some other bad failure, get out.. */
        break;
    }
    return -1;
}

static int qemuPrepareHostDevices(virConnectPtr conn,
                                  virDomainDefPtr def) {
    int i;

    /* We have to use 2 loops here. *All* devices must
     * be detached before we reset any of them, because
     * in some cases you have to reset the whole PCI,
     * which impacts all devices on it
     */

    for (i = 0 ; i < def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        if (!hostdev->managed) {
            pciDevice *dev = pciGetDevice(conn,
                                          hostdev->source.subsys.u.pci.domain,
                                          hostdev->source.subsys.u.pci.bus,
                                          hostdev->source.subsys.u.pci.slot,
                                          hostdev->source.subsys.u.pci.function);
            if (!dev)
                goto error;

            if (pciDettachDevice(conn, dev) < 0) {
                pciFreeDevice(conn, dev);
                goto error;
            }

            pciFreeDevice(conn, dev);
        } /* else {
             XXX validate that non-managed device isn't in use, eg
             by checking that device is either un-bound, or bound
             to pci-stub.ko
        } */
    }

    /* Now that all the PCI hostdevs have be dettached, we can safely
     * reset them */
    for (i = 0 ; i < def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        pciDevice *dev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = pciGetDevice(conn,
                           hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);
        if (!dev)
            goto error;

        if (pciResetDevice(conn, dev) < 0) {
            pciFreeDevice(conn, dev);
            goto error;
        }

        pciFreeDevice(conn, dev);
    }

    return 0;

error:
    return -1;
}

static int qemudDomainSetSecurityLabel(virConnectPtr conn, struct qemud_driver *driver, virDomainObjPtr vm)
{
    if (vm->def->seclabel.label != NULL)
        if (driver->securityDriver && driver->securityDriver->domainSetSecurityLabel)
            return driver->securityDriver->domainSetSecurityLabel(conn, driver->securityDriver,
                                                                 vm);
    return 0;
}

static virDomainPtr qemudDomainLookupByName(virConnectPtr conn,
                                            const char *name);

struct gemudHookData {
        virConnectPtr conn;
        virDomainObjPtr vm;
        struct qemud_driver *driver;
};

static int qemudSecurityHook(void *data) {
        struct gemudHookData *h = (struct gemudHookData *) data;

        if (qemudDomainSetSecurityLabel(h->conn, h->driver, h->vm) < 0) {
                qemudReportError(h->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Failed to set security label"));
                return -1;
        }
        return 0;
}

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom,
                              int stdin_fd) {
    const char **argv = NULL, **tmp;
    const char **progenv = NULL;
    int i, ret;
    struct stat sb;
    int *tapfds = NULL;
    int ntapfds = 0;
    unsigned int qemuCmdFlags;
    fd_set keepfd;
    const char *emulator;
    pid_t child;
    int pos = -1;
    char ebuf[1024];

    struct gemudHookData hookData;
    hookData.conn = conn;
    hookData.vm = vm;
    hookData.driver = driver;

   /* If you are using a SecurityDriver with dynamic labelling,
      then generate a security label for isolation */
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        driver->securityDriver &&
        driver->securityDriver->domainGenSecurityLabel &&
        driver->securityDriver->domainGenSecurityLabel(conn, vm) < 0)
        return -1;

    FD_ZERO(&keepfd);

    if (virDomainIsActive(vm)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("VM is already active"));
        return -1;
    }

    if (vm->def->graphics &&
        vm->def->graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics->data.vnc.autoport) {
        int port = qemudNextFreeVNCPort(driver);
        if (port < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Unable to find an unused VNC port"));
            return -1;
        }
        vm->def->graphics->data.vnc.port = port;
    }

    if (virFileMakePath(driver->logDir) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot create log directory %s"),
                             driver->logDir);
        return -1;
    }

    if((vm->logfile = qemudLogFD(conn, driver->logDir, vm->def->name)) < 0)
        return -1;

    emulator = vm->def->emulator;
    if (!emulator)
        emulator = virDomainDefDefaultEmulator(conn, vm->def, driver->caps);
    if (!emulator)
        return -1;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so its hard to feed back a useful error
     */
    if (stat(emulator, &sb) < 0) {
        virReportSystemError(conn, errno,
                             _("Cannot find QEMU binary %s"),
                             emulator);
        return -1;
    }

    if (qemudExtractVersionInfo(emulator,
                                NULL,
                                &qemuCmdFlags) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot determine QEMU argv syntax %s"),
                         emulator);
        return -1;
    }

    if (qemuPrepareHostDevices(conn, vm->def) < 0)
        return -1;

    vm->def->id = driver->nextvmid++;
    if (qemudBuildCommandLine(conn, driver, vm,
                              qemuCmdFlags, &argv, &progenv,
                              &tapfds, &ntapfds, migrateFrom) < 0) {
        close(vm->logfile);
        vm->def->id = -1;
        vm->logfile = -1;
        return -1;
    }

    tmp = progenv;
    while (*tmp) {
        if (safewrite(vm->logfile, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(vm->logfile, " ", 1) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    tmp = argv;
    while (*tmp) {
        if (safewrite(vm->logfile, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(vm->logfile, " ", 1) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    if (safewrite(vm->logfile, "\n", 1) < 0)
        VIR_WARN(_("Unable to write argv to logfile: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));

    if ((pos = lseek(vm->logfile, 0, SEEK_END)) < 0)
        VIR_WARN(_("Unable to seek to end of logfile: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));

    for (i = 0 ; i < ntapfds ; i++)
        FD_SET(tapfds[i], &keepfd);

    ret = virExecWithHook(conn, argv, progenv, &keepfd, &child,
                          stdin_fd, &vm->logfile, &vm->logfile,
                          VIR_EXEC_NONBLOCK | VIR_EXEC_DAEMON,
                          qemudSecurityHook, &hookData);

    /* wait for qemu process to to show up */
    if (ret == 0) {
        int retries = 100;
        int childstat;

        while (waitpid(child, &childstat, 0) == -1 &&
               errno == EINTR);

        if (childstat == 0) {
            while (retries) {
                if ((ret = virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) == 0)
                    break;
                usleep(100*1000);
                retries--;
            }
            if (ret) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Domain %s didn't show up\n"), vm->def->name);
                ret = -1;
            }
        } else {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Unable to daemonize QEMU process"));
            ret = -1;
        }
    }

    if (ret == 0) {
        vm->state = migrateFrom ? VIR_DOMAIN_PAUSED : VIR_DOMAIN_RUNNING;
    } else
        vm->def->id = -1;

    for (i = 0 ; argv[i] ; i++)
        VIR_FREE(argv[i]);
    VIR_FREE(argv);

    for (i = 0 ; progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);

    if (tapfds) {
        for (i = 0 ; i < ntapfds ; i++) {
            close(tapfds[i]);
        }
        VIR_FREE(tapfds);
    }

    if (ret == 0) {
        if ((qemudWaitForMonitor(conn, driver, vm, pos) < 0) ||
            (qemudDetectVcpuPIDs(conn, vm) < 0) ||
            (qemudInitCpus(conn, vm, migrateFrom) < 0) ||
            (qemudInitPasswords(conn, driver, vm) < 0) ||
            (qemudSaveDomainStatus(conn, qemu_driver, vm) < 0)) {
            qemudShutdownVMDaemon(conn, driver, vm);
            return -1;
        }
    }

    return ret;
}


static void qemudShutdownVMDaemon(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  struct qemud_driver *driver,
                                  virDomainObjPtr vm) {
    if (!virDomainIsActive(vm))
        return;

    VIR_DEBUG(_("Shutting down VM '%s'\n"), vm->def->name);

    if (virKillProcess(vm->pid, 0) == 0 &&
        virKillProcess(vm->pid, SIGTERM) < 0)
        virReportSystemError(conn, errno,
                             _("Failed to send SIGTERM to %s (%d)"),
                             vm->def->name, vm->pid);

    if (vm->monitorWatch != -1) {
        virEventRemoveHandle(vm->monitorWatch);
        vm->monitorWatch = -1;
    }

    if (close(vm->logfile) < 0) {
        char ebuf[1024];
        VIR_WARN(_("Unable to close logfile: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));
    }
    if (vm->monitor != -1)
        close(vm->monitor);
    vm->logfile = -1;
    vm->monitor = -1;

    /* shut it off for sure */
    virKillProcess(vm->pid, SIGKILL);

    /* Reset Security Labels */
    if (driver->securityDriver)
        driver->securityDriver->domainRestoreSecurityLabel(conn, vm);

    /* Clear out dynamically assigned labels */
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        VIR_FREE(vm->def->seclabel.model);
        VIR_FREE(vm->def->seclabel.label);
        VIR_FREE(vm->def->seclabel.imagelabel);
    }

    if (qemudRemoveDomainStatus(conn, driver, vm) < 0) {
        VIR_WARN(_("Failed to remove domain status for %s"),
                 vm->def->name);
    }
    vm->pid = -1;
    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;
    VIR_FREE(vm->vcpupids);
    vm->nvcpupids = 0;

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }
}


static void
qemudDispatchVMEvent(int watch, int fd, int events, void *opaque) {
    struct qemud_driver *driver = opaque;
    virDomainObjPtr vm = NULL;
    virDomainEventPtr event = NULL;
    unsigned int i;
    int quit = 0, failed = 0;

    qemuDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjPtr tmpvm = driver->domains.objs[i];
        virDomainObjLock(tmpvm);
        if (virDomainIsActive(tmpvm) &&
            tmpvm->monitorWatch == watch) {
            vm = tmpvm;
            break;
        }
        virDomainObjUnlock(tmpvm);
    }

    if (!vm)
        goto cleanup;

    if (vm->monitor != fd) {
        failed = 1;
    } else {
        if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR))
            quit = 1;
        else {
            VIR_ERROR(_("unhandled fd event %d for %s"),
                      events, vm->def->name);
            failed = 1;
        }
    }

    if (failed || quit) {
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         quit ?
                                         VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN :
                                         VIR_DOMAIN_EVENT_STOPPED_FAILED);
        qemudShutdownVMDaemon(NULL, driver, vm);
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains,
                                    vm);
            vm = NULL;
        }
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
}

static int
qemudMonitorCommandExtra(const virDomainObjPtr vm,
                         const char *cmd,
                         const char *extra,
                         const char *extraPrompt,
                         char **reply) {
    int size = 0;
    char *buf = NULL;
    size_t cmdlen = strlen(cmd);
    size_t extralen = extra ? strlen(extra) : 0;

    if (safewrite(vm->monitor, cmd, cmdlen) != cmdlen)
        return -1;
    if (safewrite(vm->monitor, "\r", 1) != 1)
        return -1;

    *reply = NULL;

    for (;;) {
        struct pollfd fd = { vm->monitor, POLLIN | POLLERR | POLLHUP, 0 };
        char *tmp;

        /* Read all the data QEMU has sent thus far */
        for (;;) {
            char data[1024];
            int got = read(vm->monitor, data, sizeof(data));

            if (got == 0)
                goto error;
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN)
                    break;
                goto error;
            }
            if (VIR_REALLOC_N(buf, size+got+1) < 0)
                goto error;

            memmove(buf+size, data, got);
            buf[size+got] = '\0';
            size += got;
        }

        /* Look for QEMU prompt to indicate completion */
        if (buf) {
            if (extra) {
                if (strstr(buf, extraPrompt) != NULL) {
                    if (safewrite(vm->monitor, extra, extralen) != extralen)
                        return -1;
                    if (safewrite(vm->monitor, "\r", 1) != 1)
                        return -1;
                    extra = NULL;
                }
            } else if ((tmp = strstr(buf, QEMU_CMD_PROMPT)) != NULL) {
                char *commptr = NULL, *nlptr = NULL;
                /* Preserve the newline */
                tmp[1] = '\0';

                /* The monitor doesn't dump clean output after we have written to
                 * it. Every character we write dumps a bunch of useless stuff,
                 * so the result looks like "cXcoXcomXcommXcommaXcommanXcommand"
                 * Try to throw away everything before the first full command
                 * occurence, and inbetween the command and the newline starting
                 * the response
                 */
                if ((commptr = strstr(buf, cmd)))
                    memmove(buf, commptr, strlen(commptr)+1);
                if ((nlptr = strchr(buf, '\n')))
                    memmove(buf+strlen(cmd), nlptr, strlen(nlptr)+1);

                break;
            }
        }
    pollagain:
        /* Need to wait for more data */
        if (poll(&fd, 1, -1) < 0) {
            if (errno == EINTR)
                goto pollagain;
            goto error;
        }
    }

    /* Log, but ignore failures to write logfile for VM */
    if (safewrite(vm->logfile, buf, strlen(buf)) < 0) {
        char ebuf[1024];
        VIR_WARN(_("Unable to log VM console data: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    *reply = buf;
    return 0;

 error:
    if (buf) {
        /* Log, but ignore failures to write logfile for VM */
        if (safewrite(vm->logfile, buf, strlen(buf)) < 0) {
            char ebuf[1024];
            VIR_WARN(_("Unable to log VM console data: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        }
        VIR_FREE(buf);
    }
    return -1;
}

static int
qemudMonitorCommand(const virDomainObjPtr vm,
                    const char *cmd,
                    char **reply) {
    return qemudMonitorCommandExtra(vm, cmd, NULL, NULL, reply);
}


/**
 * qemudProbe:
 *
 * Probe for the availability of the qemu driver, assume the
 * presence of QEmu emulation if the binaries are installed
 */
static int qemudProbe(void)
{
    if ((virFileExists("/usr/bin/qemu")) ||
        (virFileExists("/usr/bin/qemu-kvm")) ||
        (virFileExists("/usr/bin/kvm")) ||
        (virFileExists("/usr/bin/xenner")))
        return 1;

    return 0;
}

static virDrvOpenStatus qemudOpen(virConnectPtr conn,
                                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                  int flags ATTRIBUTE_UNUSED) {
    uid_t uid = getuid();

    if (qemu_driver == NULL)
        goto decline;

    if (!qemudProbe())
        goto decline;

    if (conn->uri == NULL) {
        conn->uri = xmlParseURI(uid ? "qemu:///session" : "qemu:///system");
        if (!conn->uri) {
            virReportOOMError(conn);
            return VIR_DRV_OPEN_ERROR;
        }
    } else if (conn->uri->scheme == NULL ||
               conn->uri->path == NULL)
        goto decline;

    if (STRNEQ (conn->uri->scheme, "qemu"))
        goto decline;

    if (uid != 0) {
        if (STRNEQ (conn->uri->path, "/session"))
            goto decline;
    } else { /* root */
        if (STRNEQ (conn->uri->path, "/system") &&
            STRNEQ (conn->uri->path, "/session"))
            goto decline;
    }

    conn->privateData = qemu_driver;

    return VIR_DRV_OPEN_SUCCESS;

 decline:
    return VIR_DRV_OPEN_DECLINED;
}

static int qemudClose(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;

    /* Get rid of callbacks registered for this conn */
    virDomainEventCallbackListRemoveConn(conn, driver->domainEventCallbacks);

    conn->privateData = NULL;

    return 0;
}

/* Which features are supported by this driver? */
static int
qemudSupportsFeature (virConnectPtr conn ATTRIBUTE_UNUSED, int feature)
{
    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_V2: return 1;
    default: return 0;
    }
}

static const char *qemudGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "QEMU";
}


static int kvmGetMaxVCPUs(void) {
    int maxvcpus = 1;

    int r, fd;

    fd = open(KVM_DEVICE, O_RDONLY);
    if (fd < 0) {
        virReportSystemError(NULL, errno, _("Unable to open %s"), KVM_DEVICE);
        return -1;
    }

    r = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS);
    if (r > 0)
        maxvcpus = r;

    close(fd);
    return maxvcpus;
}


static int qemudGetMaxVCPUs(virConnectPtr conn, const char *type) {
    if (!type)
        return 16;

    if (STRCASEEQ(type, "qemu"))
        return 16;

    if (STRCASEEQ(type, "kvm"))
        return kvmGetMaxVCPUs();

    if (STRCASEEQ(type, "kqemu"))
        return 1;

    qemudReportError(conn, NULL, NULL, VIR_ERR_INVALID_ARG,
                     _("unknown type '%s'"), type);
    return -1;
}

static int qemudGetNodeInfo(virConnectPtr conn,
                            virNodeInfoPtr nodeinfo) {
    return virNodeInfoPopulate(conn, nodeinfo);
}


static char *qemudGetCapabilities(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;
    char *xml;

    qemuDriverLock(driver);
    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError(conn);
    qemuDriverUnlock(driver);

    return xml;
}


#if HAVE_NUMACTL
static int
qemudNodeGetCellsFreeMemory(virConnectPtr conn,
                            unsigned long long *freeMems,
                            int startCell,
                            int maxCells)
{
    int n, lastCell, numCells;
    int ret = -1;

    if (numa_available() < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("NUMA not supported on this host"));
        goto cleanup;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > numa_max_node())
        lastCell = numa_max_node();

    for (numCells = 0, n = startCell ; n <= lastCell ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Failed to query NUMA free memory"));
            goto cleanup;
        }
        freeMems[numCells++] = mem;
    }
    ret = numCells;

cleanup:
    return ret;
}

static unsigned long long
qemudNodeGetFreeMemory (virConnectPtr conn)
{
    unsigned long long freeMem = -1;
    int n;

    if (numa_available() < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("NUMA not supported on this host"));
        goto cleanup;
    }

    for (n = 0 ; n <= numa_max_node() ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Failed to query NUMA free memory"));
            goto cleanup;
        }
        freeMem += mem;
    }

cleanup:
    return freeMem;
}

#endif

static int qemudGetProcessInfo(unsigned long long *cpuTime, int pid) {
    char proc[PATH_MAX];
    FILE *pidinfo;
    unsigned long long usertime, systime;

    if (snprintf(proc, sizeof(proc), "/proc/%d/stat", pid) >= (int)sizeof(proc)) {
        return -1;
    }

    if (!(pidinfo = fopen(proc, "r"))) {
        /*printf("cannot read pid info");*/
        /* VM probably shut down, so fake 0 */
        *cpuTime = 0;
        return 0;
    }

    if (fscanf(pidinfo, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu", &usertime, &systime) != 2) {
        qemudDebug("not enough arg");
        return -1;
    }

    /* We got jiffies
     * We want nanoseconds
     * _SC_CLK_TCK is jiffies per second
     * So calulate thus....
     */
    *cpuTime = 1000ull * 1000ull * 1000ull * (usertime + systime) / (unsigned long long)sysconf(_SC_CLK_TCK);

    qemudDebug("Got %llu %llu %llu", usertime, systime, *cpuTime);

    fclose(pidinfo);

    return 0;
}


static virDomainPtr qemudDomainLookupByID(virConnectPtr conn,
                                          int id) {
    struct qemud_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    qemuDriverLock(driver);
    vm  = virDomainFindByID(&driver->domains, id);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr qemudDomainLookupByUUID(virConnectPtr conn,
                                            const unsigned char *uuid) {
    struct qemud_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr qemudDomainLookupByName(virConnectPtr conn,
                                            const char *name) {
    struct qemud_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, name);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static int qemudGetVersion(virConnectPtr conn, unsigned long *version) {
    struct qemud_driver *driver = conn->privateData;
    int ret = -1;

    qemuDriverLock(driver);
    if (qemudExtractVersion(conn, driver) < 0)
        goto cleanup;

    *version = qemu_driver->qemuVersion;
    ret = 0;

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

static char *
qemudGetHostname (virConnectPtr conn)
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

static int qemudListDomains(virConnectPtr conn, int *ids, int nids) {
    struct qemud_driver *driver = conn->privateData;
    int got = 0, i;

    qemuDriverLock(driver);
    for (i = 0 ; i < driver->domains.count && got < nids ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (virDomainIsActive(driver->domains.objs[i]))
            ids[got++] = driver->domains.objs[i]->def->id;
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    qemuDriverUnlock(driver);

    return got;
}

static int qemudNumDomains(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;
    int n = 0, i;

    qemuDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjLock(driver->domains.objs[i]);
        if (virDomainIsActive(driver->domains.objs[i]))
            n++;
        virDomainObjUnlock(driver->domains.objs[i]);
    }
    qemuDriverUnlock(driver);

    return n;
}

static virDomainPtr qemudDomainCreate(virConnectPtr conn, const char *xml,
                                      unsigned int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    if (!(def = virDomainDefParseString(conn, driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    vm = virDomainFindByName(&driver->domains, def->name);
    if (vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("domain '%s' is already defined"),
                         def->name);
        goto cleanup;
    }
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
    if (vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(def->uuid, uuidstr);
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("domain with uuid '%s' is already defined"),
                         uuidstr);
        goto cleanup;
    }

    if (!(vm = virDomainAssignDef(conn,
                                  &driver->domains,
                                  def)))
        goto cleanup;

    def = NULL;

    if (qemudStartVMDaemon(conn, driver, vm, NULL, -1) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return dom;
}


static int qemudDomainSuspend(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    char *info;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }
    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        goto cleanup;
    }
    if (vm->state != VIR_DOMAIN_PAUSED) {
        if (qemudMonitorCommand(vm, "stop", &info) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("suspend operation failed"));
            goto cleanup;
        }
        vm->state = VIR_DOMAIN_PAUSED;
        qemudDebug("Reply %s", info);
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
        VIR_FREE(info);
    }
    if (qemudSaveDomainStatus(dom->conn, driver, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);

    if (event) {
        qemuDriverLock(driver);
        qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }
    return ret;
}


static int qemudDomainResume(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    char *info;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }
    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        goto cleanup;
    }
    if (vm->state == VIR_DOMAIN_PAUSED) {
        if (qemudMonitorCommand(vm, "cont", &info) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("resume operation failed"));
            goto cleanup;
        }
        vm->state = VIR_DOMAIN_RUNNING;
        qemudDebug("Reply %s", info);
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
        VIR_FREE(info);
    }
    if (qemudSaveDomainStatus(dom->conn, driver, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event) {
        qemuDriverLock(driver);
        qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }
    return ret;
}


static int qemudDomainShutdown(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char* info;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (qemudMonitorCommand(vm, "system_powerdown", &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("shutdown operation failed"));
        goto cleanup;
    }
    VIR_FREE(info);
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int qemudDomainDestroy(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    vm  = virDomainFindByID(&driver->domains, dom->id);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    qemudShutdownVMDaemon(dom->conn, driver, vm);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
    }
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


static char *qemudDomainGetOSType(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *type = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!(type = strdup(vm->def->os.type)))
        virReportOOMError(dom->conn);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return type;
}

/* Returns max memory in kb, 0 if error */
static unsigned long qemudDomainGetMaxMemory(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned long ret = 0;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = vm->def->maxmem;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainSetMaxMemory(virDomainPtr dom, unsigned long newmax) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (newmax < vm->def->memory) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set max memory lower than current memory"));
        goto cleanup;;
    }

    vm->def->maxmem = newmax;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("cannot set memory of an active domain"));
        goto cleanup;
    }

    if (newmem > vm->def->maxmem) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set memory higher than max memory"));
        goto cleanup;
    }

    vm->def->memory = newmem;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainGetInfo(virDomainPtr dom,
                              virDomainInfoPtr info) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (qemudGetProcessInfo(&(info->cpuTime), vm->pid) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, ("cannot read cputime for domain"));
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


static char *qemudEscape(const char *in, int shell)
{
    int len = 0;
    int i, j;
    char *out;

    /* To pass through the QEMU monitor, we need to use escape
       sequences: \r, \n, \", \\

       To pass through both QEMU + the shell, we need to escape
       the single character ' as the five characters '\\''
    */

    for (i = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
        case '\r':
        case '\n':
        case '"':
        case '\\':
            len += 2;
            break;
        case '\'':
            if (shell)
                len += 5;
            else
                len += 1;
            break;
        default:
            len += 1;
            break;
        }
    }

    if (VIR_ALLOC_N(out, len + 1) < 0)
        return NULL;

    for (i = j = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
        case '\r':
            out[j++] = '\\';
            out[j++] = 'r';
            break;
        case '\n':
            out[j++] = '\\';
            out[j++] = 'n';
            break;
        case '"':
        case '\\':
            out[j++] = '\\';
            out[j++] = in[i];
            break;
        case '\'':
            if (shell) {
                out[j++] = '\'';
                out[j++] = '\\';
                out[j++] = '\\';
                out[j++] = '\'';
                out[j++] = '\'';
            } else {
                out[j++] = in[i];
            }
            break;
        default:
            out[j++] = in[i];
            break;
        }
    }
    out[j] = '\0';

    return out;
}

static char *qemudEscapeMonitorArg(const char *in)
{
    return qemudEscape(in, 0);
}

static char *qemudEscapeShellArg(const char *in)
{
    return qemudEscape(in, 1);
}

#define QEMUD_SAVE_MAGIC "LibvirtQemudSave"
#define QEMUD_SAVE_VERSION 1

struct qemud_save_header {
    char magic[sizeof(QEMUD_SAVE_MAGIC)-1];
    int version;
    int xml_len;
    int was_running;
    int unused[16];
};

static int qemudDomainSave(virDomainPtr dom,
                           const char *path) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *command = NULL;
    char *info = NULL;
    int fd = -1;
    char *safe_path = NULL;
    char *xml = NULL;
    struct qemud_save_header header;
    int ret = -1;
    virDomainEventPtr event = NULL;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic));
    header.version = QEMUD_SAVE_VERSION;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        goto cleanup;
    }

    /* Pause */
    if (vm->state == VIR_DOMAIN_RUNNING) {
        header.was_running = 1;
        if (qemudMonitorCommand(vm, "stop", &info) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("suspend operation failed"));
            goto cleanup;
        }
        vm->state = VIR_DOMAIN_PAUSED;
        qemudDebug("Reply %s", info);
        VIR_FREE(info);
    }

    /* Get XML for the domain */
    xml = virDomainDefFormat(dom->conn, vm->def, VIR_DOMAIN_XML_SECURE);
    if (!xml) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to get domain xml"));
        goto cleanup;
    }
    header.xml_len = strlen(xml) + 1;

    /* Write header to file, followed by XML */
    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to create '%s'"), path);
        goto cleanup;
    }

    if (safewrite(fd, &header, sizeof(header)) != sizeof(header)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to write save header"));
        goto cleanup;
    }

    if (safewrite(fd, xml, header.xml_len) != header.xml_len) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to write xml"));
        goto cleanup;
    }

    if (close(fd) < 0) {
        virReportSystemError(dom->conn, errno,
                             _("unable to save file %s"),
                             path);
        goto cleanup;
    }
    fd = -1;

    /* Migrate to file */
    safe_path = qemudEscapeShellArg(path);
    if (!safe_path) {
        virReportOOMError(dom->conn);
        goto cleanup;
    }
    if (virAsprintf(&command, "migrate \"exec:"
                  "dd of='%s' oflag=append conv=notrunc 2>/dev/null"
                  "\"", safe_path) == -1) {
        virReportOOMError(dom->conn);
        command = NULL;
        goto cleanup;
    }

    if (qemudMonitorCommand(vm, command, &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("migrate operation failed"));
        goto cleanup;
    }

    DEBUG ("migrate reply: %s", info);

    /* If the command isn't supported then qemu prints:
     * unknown command: migrate" */
    if (strstr(info, "unknown command:")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                          "%s",
                          _("'migrate' not supported by this qemu"));
        goto cleanup;
    }

    /* Shut it down */
    qemudShutdownVMDaemon(dom->conn, driver, vm);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SAVED);
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
    }
    ret = 0;

cleanup:
    if (fd != -1)
        close(fd);
    VIR_FREE(xml);
    VIR_FREE(safe_path);
    VIR_FREE(command);
    VIR_FREE(info);
    if (ret != 0)
        unlink(path);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


static int qemudDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int max;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT, "%s",
                         _("cannot change vcpu count of an active domain"));
        goto cleanup;
    }

    if ((max = qemudDomainGetMaxVcpus(dom)) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("could not determine max vcpus for the domain"));
        goto cleanup;
    }

    if (nvcpus > max) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         _("requested vcpus is greater than max allowable"
                           " vcpus for the domain: %d > %d"), nvcpus, max);
        goto cleanup;
    }

    vm->def->vcpus = nvcpus;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


#if HAVE_SCHED_GETAFFINITY
static int
qemudDomainPinVcpu(virDomainPtr dom,
                   unsigned int vcpu,
                   unsigned char *cpumap,
                   int maplen) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    cpu_set_t mask;
    int i, maxcpu;
    virNodeInfo nodeinfo;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s",_("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    if (vcpu > (vm->nvcpupids-1)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         _("vcpu number out of range %d > %d"),
                         vcpu, vm->nvcpupids);
        goto cleanup;
    }

    if (virNodeInfoPopulate(dom->conn, &nodeinfo) < 0)
        goto cleanup;

    maxcpu = maplen * 8;
    if (maxcpu > nodeinfo.cpus)
        maxcpu = nodeinfo.cpus;

    CPU_ZERO(&mask);
    for (i = 0 ; i < maxcpu ; i++) {
        if ((cpumap[i/8] >> (i % 8)) & 1)
            CPU_SET(i, &mask);
    }

    if (vm->vcpupids != NULL) {
        if (sched_setaffinity(vm->vcpupids[vcpu], sizeof(mask), &mask) < 0) {
            virReportSystemError(dom->conn, errno, "%s",
                                 _("cannot set affinity"));
            goto cleanup;
        }
    } else {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("cpu affinity is not supported"));
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
qemudDomainGetVcpus(virDomainPtr dom,
                    virVcpuInfoPtr info,
                    int maxinfo,
                    unsigned char *cpumaps,
                    int maplen) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virNodeInfo nodeinfo;
    int i, v, maxcpu;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s",_("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    if (virNodeInfoPopulate(dom->conn, &nodeinfo) < 0)
        goto cleanup;

    maxcpu = maplen * 8;
    if (maxcpu > nodeinfo.cpus)
        maxcpu = nodeinfo.cpus;

    /* Clamp to actual number of vcpus */
    if (maxinfo > vm->nvcpupids)
        maxinfo = vm->nvcpupids;

    if (maxinfo >= 1) {
        if (info != NULL) {
            memset(info, 0, sizeof(*info) * maxinfo);
            for (i = 0 ; i < maxinfo ; i++) {
                info[i].number = i;
                info[i].state = VIR_VCPU_RUNNING;
                /* XXX cpu time, current pCPU mapping */
            }
        }

        if (cpumaps != NULL) {
            memset(cpumaps, 0, maplen * maxinfo);
            if (vm->vcpupids != NULL) {
                for (v = 0 ; v < maxinfo ; v++) {
                    cpu_set_t mask;
                    unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, v);
                    CPU_ZERO(&mask);

                    if (sched_getaffinity(vm->vcpupids[v], sizeof(mask), &mask) < 0) {
                        virReportSystemError(dom->conn, errno, "%s",
                                             _("cannot get affinity"));
                        goto cleanup;
                    }

                    for (i = 0 ; i < maxcpu ; i++)
                        if (CPU_ISSET(i, &mask))
                            VIR_USE_CPU(cpumap, i);
                }
            } else {
                qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                                 "%s", _("cpu affinity is not available"));
                goto cleanup;
            }
        }
    }
    ret = maxinfo;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}
#endif /* HAVE_SCHED_GETAFFINITY */


static int qemudDomainGetMaxVcpus(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *type;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!(type = virDomainVirtTypeToString(vm->def->virtType))) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unknown virt type in domain definition '%d'"),
                         vm->def->virtType);
        goto cleanup;
    }

    ret = qemudGetMaxVCPUs(dom->conn, type);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainGetSecurityLabel(virDomainPtr dom, virSecurityLabelPtr seclabel)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm;
    const char *type;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!(type = virDomainVirtTypeToString(vm->def->virtType))) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unknown virt type in domain definition '%d'"),
                         vm->def->virtType);
        goto cleanup;
    }

    /*
     * Theoretically, the pid can be replaced during this operation and
     * return the label of a different process.  If atomicity is needed,
     * further validation will be required.
     *
     * Comment from Dan Berrange:
     *
     *   Well the PID as stored in the virDomainObjPtr can't be changed
     *   because you've got a locked object.  The OS level PID could have
     *   exited, though and in extreme circumstances have cycled through all
     *   PIDs back to ours. We could sanity check that our PID still exists
     *   after reading the label, by checking that our FD connecting to the
     *   QEMU monitor hasn't seen SIGHUP/ERR on poll().
     */
    if (virDomainIsActive(vm)) {
        if (driver->securityDriver && driver->securityDriver->domainGetSecurityLabel) {
            if (driver->securityDriver->domainGetSecurityLabel(dom->conn, vm, seclabel) == -1) {
                qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Failed to get security label"));
                goto cleanup;
            }
        }
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudNodeGetSecurityModel(virConnectPtr conn, virSecurityModelPtr secmodel)
{
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    char *p;

    if (!driver->securityDriver)
        return -2;

    p = driver->caps->host.secModel.model;
    if (strlen(p) >= VIR_SECURITY_MODEL_BUFLEN-1) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("security model string exceeds max %d bytes"),
                         VIR_SECURITY_MODEL_BUFLEN-1);
        return -1;
    }
    strcpy(secmodel->model, p);

    p = driver->caps->host.secModel.doi;
    if (strlen(p) >= VIR_SECURITY_DOI_BUFLEN-1) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("security DOI string exceeds max %d bytes"),
                         VIR_SECURITY_DOI_BUFLEN-1);
        return -1;
    }
    strcpy(secmodel->doi, p);
    return 0;
}

/* TODO: check seclabel restore */
static int qemudDomainRestore(virConnectPtr conn,
                              const char *path) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int fd = -1;
    int ret = -1;
    char *xml = NULL;
    struct qemud_save_header header;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    /* Verify the header and read the XML */
    if ((fd = open(path, O_RDONLY)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot read domain image"));
        goto cleanup;
    }

    if (saferead(fd, &header, sizeof(header)) != sizeof(header)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to read qemu header"));
        goto cleanup;
    }

    if (memcmp(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic)) != 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("image magic is incorrect"));
        goto cleanup;
    }

    if (header.version > QEMUD_SAVE_VERSION) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("image version is not supported (%d > %d)"),
                         header.version, QEMUD_SAVE_VERSION);
        goto cleanup;
    }

    if (VIR_ALLOC_N(xml, header.xml_len) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (saferead(fd, xml, header.xml_len) != header.xml_len) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to read XML"));
        goto cleanup;
    }

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(conn, driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to parse XML"));
        goto cleanup;
    }

    /* Ensure the name and UUID don't already exist in an active VM */
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
    if (!vm)
        vm = virDomainFindByName(&driver->domains, def->name);
    if (vm) {
        if (virDomainIsActive(vm)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain is already active as '%s'"), vm->def->name);
            goto cleanup;
        } else {
            virDomainObjUnlock(vm);
        }
    }

    if (!(vm = virDomainAssignDef(conn,
                                  &driver->domains,
                                  def))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to assign new VM"));
        goto cleanup;
    }
    def = NULL;

    /* Set the migration source and start it up. */
    ret = qemudStartVMDaemon(conn, driver, vm, "stdio", fd);
    close(fd);
    fd = -1;
    if (ret < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to start VM"));
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains,
                                    vm);
            vm = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);

    /* If it was running before, resume it now. */
    if (header.was_running) {
        char *info;
        if (qemudMonitorCommand(vm, "cont", &info) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("failed to resume domain"));
            goto cleanup;
        }
        VIR_FREE(info);
        vm->state = VIR_DOMAIN_RUNNING;
    }
    ret = 0;

cleanup:
    virDomainDefFree(def);
    VIR_FREE(xml);
    if (fd != -1)
        close(fd);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


static char *qemudDomainDumpXML(virDomainPtr dom,
                                int flags) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(dom->conn,
                             (flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef ?
                             vm->newDef : vm->def,
                             flags);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int qemudListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    struct qemud_driver *driver = conn->privateData;
    int got = 0, i;

    qemuDriverLock(driver);
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

    qemuDriverUnlock(driver);
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    qemuDriverUnlock(driver);
    return -1;
}

static int qemudNumDefinedDomains(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;
    int n = 0, i;

    qemuDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++)
        if (!virDomainIsActive(driver->domains.objs[i]))
            n++;
    qemuDriverUnlock(driver);

    return n;
}


static int qemudDomainStart(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = qemudStartVMDaemon(dom->conn, driver, vm, NULL, -1);
    if (ret != -1)
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event) {
        qemuDriverLock(driver);
        qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }
    return ret;
}


static virDomainPtr qemudDomainDefine(virConnectPtr conn, const char *xml) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    int newVM = 1;

    qemuDriverLock(driver);
    if (!(def = virDomainDefParseString(conn, driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    vm = virDomainFindByName(&driver->domains, def->name);
    if (vm) {
        virDomainObjUnlock(vm);
        newVM = 0;
    }

    if (!(vm = virDomainAssignDef(conn,
                                  &driver->domains,
                                  def))) {
        virDomainDefFree(def);
        goto cleanup;
    }
    vm->persistent = 1;

    if (virDomainSaveConfig(conn,
                            driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     newVM ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return dom;
}

static int qemudDomainUndefine(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot delete active domain"));
        goto cleanup;
    }

    if (!vm->persistent) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(dom->conn, driver->configDir, driver->autostartDir, vm) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    virDomainRemoveInactive(&driver->domains,
                            vm);
    vm = NULL;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

/* Return the disks name for use in monitor commands */
static char *qemudDiskDeviceName(const virConnectPtr conn,
                                 const virDomainDiskDefPtr disk) {

    int busid, devid;
    int ret;
    char *devname;

    if (virDiskNameToBusDeviceIndex(disk, &busid, &devid) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot convert disk '%s' to bus/device index"),
                         disk->dst);
        return NULL;
    }

    switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            if (disk->device== VIR_DOMAIN_DISK_DEVICE_DISK)
                ret = virAsprintf(&devname, "ide%d-hd%d", busid, devid);
            else
                ret = virAsprintf(&devname, "ide%d-cd%d", busid, devid);
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
                ret = virAsprintf(&devname, "scsi%d-hd%d", busid, devid);
            else
                ret = virAsprintf(&devname, "scsi%d-cd%d", busid, devid);
            break;
        case VIR_DOMAIN_DISK_BUS_FDC:
            ret = virAsprintf(&devname, "floppy%d", devid);
            break;
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
            ret = virAsprintf(&devname, "virtio%d", devid);
            break;
        default:
            qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                             _("Unsupported disk name mapping for bus '%s'"),
                             virDomainDiskBusTypeToString(disk->bus));
            return NULL;
    }

    if (ret == -1) {
        virReportOOMError(conn);
        return NULL;
    }

    return devname;
}

static int qemudDomainChangeEjectableMedia(virConnectPtr conn,
                                           virDomainObjPtr vm,
                                           virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr origdisk = NULL, newdisk;
    char *cmd, *reply, *safe_path;
    char *devname = NULL;
    unsigned int qemuCmdFlags;
    int i;

    origdisk = NULL;
    newdisk = dev->data.disk;
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->bus == newdisk->bus &&
            STREQ(vm->def->disks[i]->dst, newdisk->dst)) {
            origdisk = vm->def->disks[i];
            break;
        }
    }

    if (!origdisk) {
        qemudReportError(conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("No device with bus '%s' and target '%s'"),
                         virDomainDiskBusTypeToString(newdisk->bus),
                         newdisk->dst);
        return -1;
    }

    if (qemudExtractVersionInfo(vm->def->emulator,
                                NULL,
                                &qemuCmdFlags) < 0) {
        qemudReportError(conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot determine QEMU argv syntax %s"),
                         vm->def->emulator);
        return -1;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE) {
        if (!(devname = qemudDiskDeviceName(conn, newdisk)))
            return -1;
    } else {
        /* Back compat for no -drive option */
        if (newdisk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
            devname = strdup(newdisk->dst);
        else if (newdisk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
                 STREQ(newdisk->dst, "hdc"))
            devname = strdup("cdrom");
        else {
            qemudReportError(conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Emulator version does not support removable "
                               "media for device '%s' and target '%s'"),
                               virDomainDiskDeviceTypeToString(newdisk->device),
                               newdisk->dst);
            return -1;
        }

        if (!devname) {
            virReportOOMError(conn);
            return -1;
        }
    }

    if (newdisk->src) {
        safe_path = qemudEscapeMonitorArg(newdisk->src);
        if (!safe_path) {
            virReportOOMError(conn);
            VIR_FREE(devname);
            return -1;
        }
        if (virAsprintf(&cmd, "change %s \"%s\"", devname, safe_path) == -1) {
            virReportOOMError(conn);
            VIR_FREE(safe_path);
            VIR_FREE(devname);
            return -1;
        }
        VIR_FREE(safe_path);

    } else if (virAsprintf(&cmd, "eject %s", devname) == -1) {
        virReportOOMError(conn);
        VIR_FREE(devname);
        return -1;
    }
    VIR_FREE(devname);

    if (qemudMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("could not change cdrom media"));
        VIR_FREE(cmd);
        return -1;
    }

    /* If the command failed qemu prints:
     * device not found, device is locked ...
     * No message is printed on success it seems */
    DEBUG ("ejectable media change reply: %s", reply);
    if (strstr(reply, "\ndevice ")) {
        qemudReportError (conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          _("changing cdrom media failed: %s"), reply);
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }
    VIR_FREE(reply);
    VIR_FREE(cmd);

    VIR_FREE(origdisk->src);
    origdisk->src = newdisk->src;
    newdisk->src = NULL;
    origdisk->type = newdisk->type;
    return 0;
}

static int qemudDomainAttachPciDiskDevice(virConnectPtr conn,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev)
{
    int ret, i;
    char *cmd, *reply, *s;
    char *safe_path;
    const char* type = virDomainDiskBusTypeToString(dev->data.disk->bus);

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            qemudReportError(conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), dev->data.disk->dst);
            return -1;
        }
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    safe_path = qemudEscapeMonitorArg(dev->data.disk->src);
    if (!safe_path) {
        virReportOOMError(conn);
        return -1;
    }

    ret = virAsprintf(&cmd, "pci_add 0 storage file=%s,if=%s",
                      safe_path, type);
    VIR_FREE(safe_path);
    if (ret == -1) {
        virReportOOMError(conn);
        return ret;
    }

    if (qemudMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         _("cannot attach %s disk"), type);
        VIR_FREE(cmd);
        return -1;
    }

    DEBUG ("pci_add reply: %s", reply);
    /* If the command succeeds qemu prints:
     * OK bus 0... */
#define PCI_ATTACH_OK_MSG "OK bus 0, slot "
    if ((s=strstr(reply, PCI_ATTACH_OK_MSG))) {
        char* dummy = s;
        s += strlen(PCI_ATTACH_OK_MSG);

        if (virStrToLong_i ((const char*)s, &dummy, 10, &dev->data.disk->slotnum) == -1)
            VIR_WARN("%s", _("Unable to parse slot number\n"));
    } else {
        qemudReportError (conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          _("adding %s disk failed"), type);
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }

    vm->def->disks[vm->def->ndisks++] = dev->data.disk;
    qsort(vm->def->disks, vm->def->ndisks, sizeof(*vm->def->disks),
          virDomainDiskQSort);

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachUsbMassstorageDevice(virConnectPtr conn,
                                                 virDomainObjPtr vm,
                                                 virDomainDeviceDefPtr dev)
{
    int ret, i;
    char *safe_path;
    char *cmd, *reply;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            qemudReportError(conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), dev->data.disk->dst);
            return -1;
        }
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    safe_path = qemudEscapeMonitorArg(dev->data.disk->src);
    if (!safe_path) {
        virReportOOMError(conn);
        return -1;
    }

    ret = virAsprintf(&cmd, "usb_add disk:%s", safe_path);
    VIR_FREE(safe_path);
    if (ret == -1) {
        virReportOOMError(conn);
        return ret;
    }

    if (qemudMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot attach usb disk"));
        VIR_FREE(cmd);
        return -1;
    }

    DEBUG ("attach_usb reply: %s", reply);
    /* If the command failed qemu prints:
     * Could not add ... */
    if (strstr(reply, "Could not add ")) {
        qemudReportError (conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s",
                          _("adding usb disk failed"));
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }

    vm->def->disks[vm->def->ndisks++] = dev->data.disk;
    qsort(vm->def->disks, vm->def->ndisks, sizeof(*vm->def->disks),
          virDomainDiskQSort);

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachHostDevice(virConnectPtr conn,
                                       virDomainObjPtr vm,
                                       virDomainDeviceDefPtr dev)
{
    int ret;
    char *cmd, *reply;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    if (dev->data.hostdev->source.subsys.u.usb.vendor) {
        ret = virAsprintf(&cmd, "usb_add host:%.4x:%.4x",
                          dev->data.hostdev->source.subsys.u.usb.vendor,
                          dev->data.hostdev->source.subsys.u.usb.product);
    } else {
        ret = virAsprintf(&cmd, "usb_add host:%.3d.%.3d",
                          dev->data.hostdev->source.subsys.u.usb.bus,
                          dev->data.hostdev->source.subsys.u.usb.device);
    }
    if (ret == -1) {
        virReportOOMError(conn);
        return -1;
    }

    if (qemudMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot attach usb device"));
        VIR_FREE(cmd);
        return -1;
    }

    DEBUG ("attach_usb reply: %s", reply);
    /* If the command failed qemu prints:
     * Could not add ... */
    if (strstr(reply, "Could not add ")) {
        qemudReportError (conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s",
                          _("adding usb device failed"));
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = dev->data.hostdev;

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachDevice(virDomainPtr dom,
                                   const char *xml) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDeviceDefPtr dev = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        qemuDriverUnlock(driver);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemuDriverUnlock(driver);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot attach device on inactive domain"));
        goto cleanup;
    }

    dev = virDomainDeviceDefParse(dom->conn, driver->caps, vm->def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    qemuDriverUnlock(driver);
    if (dev == NULL)
        goto cleanup;


    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        switch (dev->data.disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            ret = qemudDomainChangeEjectableMedia(dom->conn, vm, dev);
            break;

        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                ret = qemudDomainAttachUsbMassstorageDevice(dom->conn, vm, dev);
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
                       dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
                ret = qemudDomainAttachPciDiskDevice(dom->conn, vm, dev);
            } else {
                qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                                 _("disk bus '%s' cannot be hotplugged."),
                                 virDomainDiskBusTypeToString(dev->data.disk->bus));
                goto cleanup;
            }
            if (driver->securityDriver)
                driver->securityDriver->domainSetSecurityImageLabel(dom->conn, vm, dev);
            break;

        default:
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                             _("disk device type '%s' cannot be hotplugged"),
                             virDomainDiskDeviceTypeToString(dev->data.disk->device));
            goto cleanup;
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
               dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
               dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
        ret = qemudDomainAttachHostDevice(dom->conn, vm, dev);
    } else {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         _("device type '%s' cannot be attached"),
                         virDomainDeviceTypeToString(dev->type));
        goto cleanup;
    }

    if (!ret && qemudSaveDomainStatus(dom->conn, driver, vm) < 0)
        ret = -1;

cleanup:
    if (ret < 0)
        virDomainDeviceDefFree(dev);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainDetachPciDiskDevice(virConnectPtr conn,
                                          virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    int i, ret = -1;
    char *cmd = NULL;
    char *reply = NULL;
    virDomainDiskDefPtr detach = NULL;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            detach = vm->def->disks[i];
            break;
        }
    }

    if (!detach) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("disk %s not found"), dev->data.disk->dst);
        goto cleanup;
    }

    if (detach->slotnum < 1) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("disk %s cannot be detached - invalid slot number %d"),
                           detach->dst, detach->slotnum);
        goto cleanup;
    }

    if (virAsprintf(&cmd, "pci_del 0 %d", detach->slotnum) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (qemudMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          _("failed to execute detach disk %s command"), detach->dst);
        goto cleanup;
    }

    DEBUG ("pci_del reply: %s", reply);
    /* If the command fails due to a wrong slot qemu prints: invalid slot,
     * nothing is printed on success */
    if (strstr(reply, "invalid slot")) {
        qemudReportError (conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          _("failed to detach disk %s: invalid slot %d"),
                          detach->dst, detach->slotnum);
        goto cleanup;
    }

    if (vm->def->ndisks > 1) {
        vm->def->disks[i] = vm->def->disks[--vm->def->ndisks];
        if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks) < 0) {
            virReportOOMError(conn);
            goto cleanup;
        }
        qsort(vm->def->disks, vm->def->ndisks, sizeof(*vm->def->disks),
              virDomainDiskQSort);
    } else {
        VIR_FREE(vm->def->disks[0]);
        vm->def->ndisks = 0;
    }
    ret = 0;

cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}

static int qemudDomainDetachDevice(virDomainPtr dom,
                                   const char *xml) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDeviceDefPtr dev = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        qemuDriverUnlock(driver);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemuDriverUnlock(driver);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot detach device on inactive domain"));
        goto cleanup;
    }

    dev = virDomainDeviceDefParse(dom->conn, driver->caps, vm->def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    qemuDriverUnlock(driver);
    if (dev == NULL)
        goto cleanup;


    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
         dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)) {
        ret = qemudDomainDetachPciDiskDevice(dom->conn, vm, dev);
        if (driver->securityDriver)
            driver->securityDriver->domainRestoreSecurityImageLabel(dom->conn, vm, dev);
    }
    else
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("only SCSI or virtio disk device can be detached dynamically"));

    if (!ret && qemudSaveDomainStatus(dom->conn, driver, vm) < 0)
        ret = -1;

cleanup:
    virDomainDeviceDefFree(dev);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainGetAutostart(virDomainPtr dom,
                                   int *autostart) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    *autostart = vm->autostart;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainSetAutostart(virDomainPtr dom,
                                   int autostart) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!vm->persistent) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if ((configFile = virDomainConfigFile(dom->conn, driver->configDir, vm->def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virDomainConfigFile(dom->conn, driver->autostartDir, vm->def->name)) == NULL)
            goto cleanup;

        if (autostart) {
            int err;

            if ((err = virFileMakePath(driver->autostartDir))) {
                virReportSystemError(dom->conn, err,
                                     _("cannot create autostart directory %s"),
                                     driver->autostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(dom->conn, errno,
                                     _("Failed to create symlink '%s to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(dom->conn, errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto cleanup;
            }
        }

        vm->autostart = autostart;
    }
    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

/* This uses the 'info blockstats' monitor command which was
 * integrated into both qemu & kvm in late 2007.  If the command is
 * not supported we detect this and return the appropriate error.
 */
static int
qemudDomainBlockStats (virDomainPtr dom,
                       const char *path,
                       struct _virDomainBlockStats *stats)
{
    struct qemud_driver *driver = dom->conn->privateData;
    char *dummy, *info = NULL;
    const char *p, *eol;
    const char *qemu_dev_name = NULL;
    size_t len;
    int i, ret = -1;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    qemuDriverUnlock(driver);
    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }
    if (!virDomainIsActive (vm)) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("domain is not running"));
        goto cleanup;
    }

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(path, vm->def->disks[i]->dst)) {
            disk = vm->def->disks[i];
            break;
        }
    }

    if (!disk) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          _("invalid path: %s"), path);
        goto cleanup;
    }

    qemu_dev_name = qemudDiskDeviceName(dom->conn, disk);
    if (!qemu_dev_name)
        goto cleanup;
    len = strlen (qemu_dev_name);

    if (qemudMonitorCommand (vm, "info blockstats", &info) < 0) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("'info blockstats' command failed"));
        goto cleanup;
    }
    DEBUG ("info blockstats reply: %s", info);

    /* If the command isn't supported then qemu prints the supported
     * info commands, so the output starts "info ".  Since this is
     * unlikely to be the name of a block device, we can use this
     * to detect if qemu supports the command.
     */
    if (strstr(info, "\ninfo ")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                          "%s",
                          _("'info blockstats' not supported by this qemu"));
        goto cleanup;
    }

    stats->rd_req = -1;
    stats->rd_bytes = -1;
    stats->wr_req = -1;
    stats->wr_bytes = -1;
    stats->errs = -1;

    /* The output format for both qemu & KVM is:
     *   blockdevice: rd_bytes=% wr_bytes=% rd_operations=% wr_operations=%
     *   (repeated for each block device)
     * where '%' is a 64 bit number.
     */
    p = info;

    while (*p) {
        if (STREQLEN (p, qemu_dev_name, len)
            && p[len] == ':' && p[len+1] == ' ') {

            eol = strchr (p, '\n');
            if (!eol)
                eol = p + strlen (p);

            p += len+2;         /* Skip to first label. */

            while (*p) {
                if (STRPREFIX (p, "rd_bytes=")) {
                    p += 9;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->rd_bytes) == -1)
                        DEBUG ("error reading rd_bytes: %s", p);
                } else if (STRPREFIX (p, "wr_bytes=")) {
                    p += 9;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->wr_bytes) == -1)
                        DEBUG ("error reading wr_bytes: %s", p);
                } else if (STRPREFIX (p, "rd_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->rd_req) == -1)
                        DEBUG ("error reading rd_req: %s", p);
                } else if (STRPREFIX (p, "wr_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->wr_req) == -1)
                        DEBUG ("error reading wr_req: %s", p);
                } else
                    DEBUG ("unknown block stat near %s", p);

                /* Skip to next label. */
                p = strchr (p, ' ');
                if (!p || p >= eol) break;
                p++;
            }
            ret = 0;
            goto cleanup;
        }

        /* Skip to next line. */
        p = strchr (p, '\n');
        if (!p) break;
        p++;
    }

    /* If we reach here then the device was not found. */
    qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                      _("device not found: %s (%s)"), path, qemu_dev_name);
 cleanup:
    VIR_FREE(qemu_dev_name);
    VIR_FREE(info);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

#ifdef __linux__
static int
qemudDomainInterfaceStats (virDomainPtr dom,
                           const char *path,
                           struct _virDomainInterfaceStats *stats)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int i;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!path || path[0] == '\0') {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("NULL or empty path"));
        goto cleanup;
    }

    /* Check the path is one of the domain's network interfaces. */
    for (i = 0 ; i < vm->def->nnets ; i++) {
        if (vm->def->nets[i]->ifname &&
            STREQ (vm->def->nets[i]->ifname, path)) {
            ret = 0;
            break;
        }
    }

    if (ret == 0)
        ret = linuxDomainInterfaceStats (dom->conn, path, stats);
    else
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          _("invalid path, '%s' is not a known interface"), path);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}
#else
static int
qemudDomainInterfaceStats (virDomainPtr dom,
                           const char *path ATTRIBUTE_UNUSED,
                           struct _virDomainInterfaceStats *stats ATTRIBUTE_UNUSED)
    qemudReportError (dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                      "%s", __FUNCTION__);
    return -1;
}
#endif

static int
qemudDomainBlockPeek (virDomainPtr dom,
                      const char *path,
                      unsigned long long offset, size_t size,
                      void *buffer,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int fd = -1, ret = -1, i;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!path || path[0] == '\0') {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("NULL or empty path"));
        goto cleanup;
    }

    /* Check the path belongs to this domain. */
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->src != NULL &&
            STREQ (vm->def->disks[i]->src, path)) {
            ret = 0;
            break;
        }
    }

    if (ret == 0) {
        ret = -1;
        /* The path is correct, now try to open it and get its size. */
        fd = open (path, O_RDONLY);
        if (fd == -1) {
            virReportSystemError (dom->conn, errno,
                                  _("%s: failed to open"), path);
            goto cleanup;
        }

        /* Seek and read. */
        /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
         * be 64 bits on all platforms.
         */
        if (lseek (fd, offset, SEEK_SET) == (off_t) -1 ||
            saferead (fd, buffer, size) == (ssize_t) -1) {
            virReportSystemError (dom->conn, errno,
                                  _("%s: failed to seek or read"), path);
            goto cleanup;
        }

        ret = 0;
    } else {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          "%s", _("invalid path"));
    }

cleanup:
    if (fd >= 0)
        close (fd);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
qemudDomainMemoryPeek (virDomainPtr dom,
                       unsigned long long offset, size_t size,
                       void *buffer,
                       unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char cmd[256], *info = NULL;
    char tmp[] = TEMPDIR "/qemu.mem.XXXXXX";
    int fd = -1, ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    qemuDriverUnlock(driver);

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (flags != VIR_MEMORY_VIRTUAL) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          "%s", _("QEMU driver only supports virtual memory addrs"));
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        goto cleanup;
    }

    /* Create a temporary filename. */
    if ((fd = mkstemp (tmp)) == -1) {
        virReportSystemError (dom->conn, errno,
                              _("mkstemp(\"%s\") failed"), tmp);
        goto cleanup;
    }

    /* Issue the memsave command. */
    snprintf (cmd, sizeof cmd, "memsave %llu %zi \"%s\"", offset, size, tmp);
    if (qemudMonitorCommand (vm, cmd, &info) < 0) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("'memsave' command failed"));
        goto cleanup;
    }

    DEBUG ("memsave reply: %s", info);

    /* Read the memory file into buffer. */
    if (saferead (fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError (dom->conn, errno,
                              _("failed to read temporary file "
                                "created with template %s"), tmp);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(info);
    if (fd >= 0) close (fd);
    unlink (tmp);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int
qemudDomainEventRegister (virConnectPtr conn,
                          virConnectDomainEventCallback callback,
                          void *opaque,
                          virFreeCallback freecb)
{
    struct qemud_driver *driver = conn->privateData;
    int ret;

    qemuDriverLock(driver);
    ret = virDomainEventCallbackListAdd(conn, driver->domainEventCallbacks,
                                        callback, opaque, freecb);
    qemuDriverUnlock(driver);

    return ret;
}

static int
qemudDomainEventDeregister (virConnectPtr conn,
                            virConnectDomainEventCallback callback)
{
    struct qemud_driver *driver = conn->privateData;
    int ret;

    qemuDriverLock(driver);
    if (driver->domainEventDispatching)
        ret = virDomainEventCallbackListMarkDelete(conn, driver->domainEventCallbacks,
                                                   callback);
    else
        ret = virDomainEventCallbackListRemove(conn, driver->domainEventCallbacks,
                                               callback);
    qemuDriverUnlock(driver);

    return ret;
}

static void qemuDomainEventDispatchFunc(virConnectPtr conn,
                                        virDomainEventPtr event,
                                        virConnectDomainEventCallback cb,
                                        void *cbopaque,
                                        void *opaque)
{
    struct qemud_driver *driver = opaque;

    /* Drop the lock whle dispatching, for sake of re-entrancy */
    qemuDriverUnlock(driver);
    virDomainEventDispatchDefaultFunc(conn, event, cb, cbopaque, NULL);
    qemuDriverLock(driver);
}

static void qemuDomainEventFlush(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    struct qemud_driver *driver = opaque;
    virDomainEventQueue tempQueue;

    qemuDriverLock(driver);

    driver->domainEventDispatching = 1;

    /* Copy the queue, so we're reentrant safe */
    tempQueue.count = driver->domainEventQueue->count;
    tempQueue.events = driver->domainEventQueue->events;
    driver->domainEventQueue->count = 0;
    driver->domainEventQueue->events = NULL;

    virEventUpdateTimeout(driver->domainEventTimer, -1);
    virDomainEventQueueDispatch(&tempQueue,
                                driver->domainEventCallbacks,
                                qemuDomainEventDispatchFunc,
                                driver);

    /* Purge any deleted callbacks */
    virDomainEventCallbackListPurgeMarked(driver->domainEventCallbacks);

    driver->domainEventDispatching = 0;
    qemuDriverUnlock(driver);
}


/* driver must be locked before calling */
static void qemuDomainEventQueue(struct qemud_driver *driver,
                                 virDomainEventPtr event)
{
    if (virDomainEventQueuePush(driver->domainEventQueue,
                                event) < 0)
        virDomainEventFree(event);
    if (qemu_driver->domainEventQueue->count == 1)
        virEventUpdateTimeout(driver->domainEventTimer, 0);
}

/* Migration support. */

/* Prepare is the first step, and it runs on the destination host.
 *
 * This starts an empty VM listening on a TCP port.
 */
static int
qemudDomainMigratePrepare2 (virConnectPtr dconn,
                            char **cookie ATTRIBUTE_UNUSED,
                            int *cookielen ATTRIBUTE_UNUSED,
                            const char *uri_in,
                            char **uri_out,
                            unsigned long flags ATTRIBUTE_UNUSED,
                            const char *dname,
                            unsigned long resource ATTRIBUTE_UNUSED,
                            const char *dom_xml)
{
    static int port = 0;
    struct qemud_driver *driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int this_port;
    char hostname [HOST_NAME_MAX+1];
    char migrateFrom [64];
    const char *p;
    virDomainEventPtr event = NULL;
    int ret = -1;;

    *uri_out = NULL;

    qemuDriverLock(driver);
    if (!dom_xml) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                          "%s", _("no domain XML passed"));
        goto cleanup;
    }

    /* The URI passed in may be NULL or a string "tcp://somehostname:port".
     *
     * If the URI passed in is NULL then we allocate a port number
     * from our pool of port numbers and return a URI of
     * "tcp://ourhostname:port".
     *
     * If the URI passed in is not NULL then we try to parse out the
     * port number and use that (note that the hostname is assumed
     * to be a correct hostname which refers to the target machine).
     */
    if (uri_in == NULL) {
        this_port = QEMUD_MIGRATION_FIRST_PORT + port++;
        if (port == QEMUD_MIGRATION_NUM_PORTS) port = 0;

        /* Get hostname */
        if (gethostname (hostname, HOST_NAME_MAX+1) == -1) {
            virReportSystemError (dconn, errno,
                                  "%s", _("failed to determine host name"));
            goto cleanup;
        }

        /* Caller frees */
        if (virAsprintf(uri_out, "tcp:%s:%d", hostname, this_port) < 0) {
            virReportOOMError (dconn);
            goto cleanup;
        }
    } else {
        /* Check the URI starts with "tcp:".  We will escape the
         * URI when passing it to the qemu monitor, so bad
         * characters in hostname part don't matter.
         */
        if (!STREQLEN (uri_in, "tcp:", 6)) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_INVALID_ARG,
                  "%s", _("only tcp URIs are supported for KVM migrations"));
            goto cleanup;
        }

        /* Get the port number. */
        p = strrchr (uri_in, ':');
        p++; /* definitely has a ':' in it, see above */
        this_port = virParseNumber (&p);
        if (this_port == -1 || p-uri_in != strlen (uri_in)) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_INVALID_ARG,
                              "%s", _("URI did not have ':port' at the end"));
            goto cleanup;
        }
    }

    /* Parse the domain XML. */
    if (!(def = virDomainDefParseString(dconn, driver->caps, dom_xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("failed to parse XML"));
        goto cleanup;
    }

    /* Target domain name, maybe renamed. */
    dname = dname ? dname : def->name;

#if 1
    /* Ensure the name and UUID don't already exist in an active VM */
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
#else
    /* For TESTING ONLY you can change #if 1 -> #if 0 above and use
     * this code which lets you do localhost migrations.  You must still
     * supply a fresh 'dname' but this code assigns a random UUID.
     */
    if (virUUIDGenerate (def->uuid) == -1) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
            _("could not generate random UUID"));
        goto cleanup;
    }
#endif

    if (!vm) vm = virDomainFindByName(&driver->domains, dname);
    if (vm) {
        if (virDomainIsActive(vm)) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                              _("domain with the same name or UUID already exists as '%s'"),
                              vm->def->name);
            goto cleanup;
        }
    }

    if (!(vm = virDomainAssignDef(dconn,
                                  &driver->domains,
                                  def))) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("failed to assign new VM"));
        goto cleanup;
    }
    def = NULL;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming tcp:0.0.0.0:port
     */
    snprintf (migrateFrom, sizeof (migrateFrom), "tcp:0.0.0.0:%d", this_port);
    if (qemudStartVMDaemon (dconn, driver, vm, migrateFrom, -1) < 0) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("failed to start listening VM"));
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

cleanup:
    virDomainDefFree(def);
    if (ret != 0) {
        VIR_FREE(*uri_out);
    }
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

/* Perform is the second step, and it runs on the source host. */
static int
qemudDomainMigratePerform (virDomainPtr dom,
                           const char *cookie ATTRIBUTE_UNUSED,
                           int cookielen ATTRIBUTE_UNUSED,
                           const char *uri,
                           unsigned long flags ATTRIBUTE_UNUSED,
                           const char *dname ATTRIBUTE_UNUSED,
                           unsigned long resource)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    char *safe_uri;
    char cmd[HOST_NAME_MAX+50];
    char *info = NULL;
    int ret = -1;
    int paused = 0;

    qemuDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!(flags & VIR_MIGRATE_LIVE)) {
        /* Pause domain for non-live migration */
        if (qemudMonitorCommand (vm, "stop", &info) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("off-line migration specified, but suspend operation failed"));
            goto cleanup;
        }
        DEBUG ("stop reply: %s", info);
        VIR_FREE(info);
        paused = 1;

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
        if (event)
            qemuDomainEventQueue(driver, event);
        event = NULL;
    }

    if (resource > 0) {
        /* Issue migrate_set_speed command.  Don't worry if it fails. */
        snprintf (cmd, sizeof cmd, "migrate_set_speed %lum", resource);
        qemudMonitorCommand (vm, cmd, &info);

        DEBUG ("migrate_set_speed reply: %s", info);
        VIR_FREE (info);
    }

    /* Issue the migrate command. */
    safe_uri = qemudEscapeMonitorArg (uri);
    if (!safe_uri) {
        virReportOOMError (dom->conn);
        goto cleanup;
    }
    snprintf (cmd, sizeof cmd, "migrate \"%s\"", safe_uri);
    VIR_FREE (safe_uri);

    if (qemudMonitorCommand (vm, cmd, &info) < 0) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("migrate operation failed"));
        goto cleanup;
    }

    DEBUG ("migrate reply: %s", info);

    /* Now check for "fail" in the output string */
    if (strstr(info, "fail") != NULL) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          _("migrate failed: %s"), info);
        goto cleanup;
    }

    /* Clean up the source domain. */
    qemudShutdownVMDaemon (dom->conn, driver, vm);
    paused = 0;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }
    ret = 0;

cleanup:
    /* Note that we have to free info *first*, since we are re-using the
     * variable below (and otherwise might cause a memory leak)
     */
    VIR_FREE(info);

    if (paused) {
        /* we got here through some sort of failure; start the domain again */
        if (qemudMonitorCommand (vm, "cont", &info) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best
             */
            VIR_ERROR(_("Failed to resume guest %s after failure\n"),
                      vm->def->name);
        }
        else {
            DEBUG ("cont reply: %s", info);
            VIR_FREE(info);
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    }

    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

/* Finish is the third and final step, and it runs on the destination host. */
static virDomainPtr
qemudDomainMigrateFinish2 (virConnectPtr dconn,
                           const char *dname,
                           const char *cookie ATTRIBUTE_UNUSED,
                           int cookielen ATTRIBUTE_UNUSED,
                           const char *uri ATTRIBUTE_UNUSED,
                           unsigned long flags ATTRIBUTE_UNUSED,
                           int retcode)
{
    struct qemud_driver *driver = dconn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    char *info = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dname);
    if (!vm) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching name %s"), dname);
        goto cleanup;
    }

    /* Did the migration go as planned?  If yes, return the domain
     * object, but if no, clean up the empty qemu process.
     */
    if (retcode == 0) {
        dom = virGetDomain (dconn, vm->def->name, vm->def->uuid);
        VIR_FREE(info);
        vm->state = VIR_DOMAIN_RUNNING;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    } else {
        qemudShutdownVMDaemon (dconn, driver, vm);
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FAILED);
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return dom;
}

static int
qemudNodeDeviceGetPciInfo (virNodeDevicePtr dev,
                           unsigned *domain,
                           unsigned *bus,
                           unsigned *slot,
                           unsigned *function)
{
    virNodeDeviceDefPtr def = NULL;
    virNodeDevCapsDefPtr cap;
    char *xml = NULL;
    int ret = -1;

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto out;

    def = virNodeDeviceDefParseString(dev->conn, xml);
    if (!def)
        goto out;

    cap = def->caps;
    while (cap) {
        if (cap->type == VIR_NODE_DEV_CAP_PCI_DEV) {
            *domain   = cap->data.pci_dev.domain;
            *bus      = cap->data.pci_dev.bus;
            *slot     = cap->data.pci_dev.slot;
            *function = cap->data.pci_dev.function;
            break;
        }

        cap = cap->next;
    }

    if (!cap) {
        qemudReportError(dev->conn, NULL, NULL, VIR_ERR_INVALID_ARG,
                         _("device %s is not a PCI device"), dev->name);
        goto out;
    }

    ret = 0;
out:
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}

static int
qemudNodeDeviceDettach (virNodeDevicePtr dev)
{
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (qemudNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(dev->conn, domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciDettachDevice(dev->conn, pci) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(dev->conn, pci);
    return ret;
}

static int
qemudNodeDeviceReAttach (virNodeDevicePtr dev)
{
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (qemudNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(dev->conn, domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciReAttachDevice(dev->conn, pci) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(dev->conn, pci);
    return ret;
}

static int
qemudNodeDeviceReset (virNodeDevicePtr dev)
{
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (qemudNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(dev->conn, domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciResetDevice(dev->conn, pci) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(dev->conn, pci);
    return ret;
}

static virDriver qemuDriver = {
    VIR_DRV_QEMU,
    "QEMU",
    qemudOpen, /* open */
    qemudClose, /* close */
    qemudSupportsFeature, /* supports_feature */
    qemudGetType, /* type */
    qemudGetVersion, /* version */
    qemudGetHostname, /* hostname */
    NULL, /* URI  */
    qemudGetMaxVCPUs, /* getMaxVcpus */
    qemudGetNodeInfo, /* nodeGetInfo */
    qemudGetCapabilities, /* getCapabilities */
    qemudListDomains, /* listDomains */
    qemudNumDomains, /* numOfDomains */
    qemudDomainCreate, /* domainCreateXML */
    qemudDomainLookupByID, /* domainLookupByID */
    qemudDomainLookupByUUID, /* domainLookupByUUID */
    qemudDomainLookupByName, /* domainLookupByName */
    qemudDomainSuspend, /* domainSuspend */
    qemudDomainResume, /* domainResume */
    qemudDomainShutdown, /* domainShutdown */
    NULL, /* domainReboot */
    qemudDomainDestroy, /* domainDestroy */
    qemudDomainGetOSType, /* domainGetOSType */
    qemudDomainGetMaxMemory, /* domainGetMaxMemory */
    qemudDomainSetMaxMemory, /* domainSetMaxMemory */
    qemudDomainSetMemory, /* domainSetMemory */
    qemudDomainGetInfo, /* domainGetInfo */
    qemudDomainSave, /* domainSave */
    qemudDomainRestore, /* domainRestore */
    NULL, /* domainCoreDump */
    qemudDomainSetVcpus, /* domainSetVcpus */
#if HAVE_SCHED_GETAFFINITY
    qemudDomainPinVcpu, /* domainPinVcpu */
    qemudDomainGetVcpus, /* domainGetVcpus */
#else
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
#endif
    qemudDomainGetMaxVcpus, /* domainGetMaxVcpus */
    qemudDomainGetSecurityLabel, /* domainGetSecurityLabel */
    qemudNodeGetSecurityModel, /* nodeGetSecurityModel */
    qemudDomainDumpXML, /* domainDumpXML */
    qemudListDefinedDomains, /* listDomains */
    qemudNumDefinedDomains, /* numOfDomains */
    qemudDomainStart, /* domainCreate */
    qemudDomainDefine, /* domainDefineXML */
    qemudDomainUndefine, /* domainUndefine */
    qemudDomainAttachDevice, /* domainAttachDevice */
    qemudDomainDetachDevice, /* domainDetachDevice */
    qemudDomainGetAutostart, /* domainGetAutostart */
    qemudDomainSetAutostart, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare (v1) */
    qemudDomainMigratePerform, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    qemudDomainBlockStats, /* domainBlockStats */
    qemudDomainInterfaceStats, /* domainInterfaceStats */
    qemudDomainBlockPeek, /* domainBlockPeek */
    qemudDomainMemoryPeek, /* domainMemoryPeek */
#if HAVE_NUMACTL
    qemudNodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    qemudNodeGetFreeMemory,  /* getFreeMemory */
#else
    NULL, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
#endif
    qemudDomainEventRegister, /* domainEventRegister */
    qemudDomainEventDeregister, /* domainEventDeregister */
    qemudDomainMigratePrepare2, /* domainMigratePrepare2 */
    qemudDomainMigrateFinish2, /* domainMigrateFinish2 */
    qemudNodeDeviceDettach, /* nodeDeviceDettach */
    qemudNodeDeviceReAttach, /* nodeDeviceReAttach */
    qemudNodeDeviceReset, /* nodeDeviceReset */
};


static virStateDriver qemuStateDriver = {
    .initialize = qemudStartup,
    .cleanup = qemudShutdown,
    .reload = qemudReload,
    .active = qemudActive,
};

int qemuRegister(void) {
    virRegisterDriver(&qemuDriver);
    virRegisterStateDriver(&qemuStateDriver);
    return 0;
}
