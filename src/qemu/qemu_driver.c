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
#include <stdbool.h>
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
#include <sys/un.h>

#if HAVE_SCHED_H
#include <sched.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "qemu_driver.h"
#include "qemu_conf.h"
#include "qemu_monitor_text.h"
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
#include "hostusb.h"
#include "security/security_driver.h"
#include "cgroup.h"
#include "libvirt_internal.h"


#define VIR_FROM_THIS VIR_FROM_QEMU

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

static int qemuDetectVcpuPIDs(virConnectPtr conn,
                              virDomainObjPtr vm);

static int qemuUpdateActivePciHostdevs(struct qemud_driver *driver,
                                       virDomainDefPtr def);

static struct qemud_driver *qemu_driver = NULL;

static int qemuCgroupControllerActive(struct qemud_driver *driver,
                                      int controller)
{
    if (driver->cgroup == NULL)
        return 0;
    if (driver->cgroupControllers & (1 << controller))
        return 1;
    return 0;
}

static int
qemudLogFD(virConnectPtr conn, struct qemud_driver *driver, const char* name)
{
    char logfile[PATH_MAX];
    mode_t logmode;
    int ret, fd = -1;

    if ((ret = snprintf(logfile, sizeof(logfile), "%s/%s.log",
                        driver->logDir, name))
        < 0 || ret >= sizeof(logfile)) {
        virReportOOMError(conn);
        return -1;
    }

    logmode = O_CREAT | O_WRONLY;
    /* Only logrotate files in /var/log, so only append if running privileged */
    if (driver->privileged)
        logmode |= O_APPEND;
    else
        logmode |= O_TRUNC;

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
    virConnectPtr conn = virConnectOpen(driver->privileged ?
                                        "qemu:///system" :
                                        "qemu:///session");
    /* Ignoring NULL conn which is mostly harmless here */

    qemuDriverLock(driver);
    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjPtr vm = driver->domains.objs[i];
        virDomainObjLock(vm);
        if (vm->autostart &&
            !virDomainIsActive(vm)) {
            int ret;

            virResetLastError();
            ret = qemudStartVMDaemon(conn, driver, vm, NULL, -1);
            if (ret < 0) {
                virErrorPtr err = virGetLastError();
                VIR_ERROR(_("Failed to autostart VM '%s': %s\n"),
                          vm->def->name,
                          err ? err->message : "");
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
    qemuDriverUnlock(driver);

    if (conn)
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
                            int reconnect);


/*
 * Open an existing VM's monitor, re-detect VCPU threads
 * and re-reserve the security labels in use
 */
static int
qemuReconnectDomain(struct qemud_driver *driver,
                    virDomainObjPtr obj)
{
    int rc;

    if ((rc = qemudOpenMonitor(NULL, driver, obj, 1)) != 0) {
        VIR_ERROR(_("Failed to reconnect monitor for %s: %d\n"),
                  obj->def->name, rc);
        goto error;
    }

    if (qemuUpdateActivePciHostdevs(driver, obj->def) < 0) {
        goto error;
    }

    if (obj->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        driver->securityDriver &&
        driver->securityDriver->domainReserveSecurityLabel &&
        driver->securityDriver->domainReserveSecurityLabel(NULL, obj) < 0)
        return -1;

    if (obj->def->id >= driver->nextvmid)
        driver->nextvmid = obj->def->id + 1;

    return 0;

error:
    return -1;
}

/**
 * qemudReconnectVMs
 *
 * Try to re-open the resources for live VMs that we care
 * about.
 */
static void
qemuReconnectDomains(struct qemud_driver *driver)
{
    int i;

    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjPtr obj = driver->domains.objs[i];

        virDomainObjLock(obj);
        if (qemuReconnectDomain(driver, obj) < 0) {
            /* If we can't get the monitor back, then kill the VM
             * so user has ability to start it again later without
             * danger of ending up running twice */
            qemudShutdownVMDaemon(NULL, driver, obj);
        }
        virDomainObjUnlock(obj);
    }
}


static int
qemudSecurityCapsInit(virSecurityDriverPtr secdrv,
                      virCapsPtr caps)
{
    const char *doi, *model;

    doi = virSecurityDriverGetDOI(secdrv);
    model = virSecurityDriverGetModel(secdrv);

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

    VIR_DEBUG("Initialized caps for security driver \"%s\" with "
              "DOI \"%s\"", model, doi);

    return 0;
}


static int
qemudSecurityInit(struct qemud_driver *qemud_drv)
{
    int ret;
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

    VIR_INFO("Initialized security driver %s", security_drv->name);

    /*
     * Add security policy host caps now that the security driver is
     * initialized.
     */
    return qemudSecurityCapsInit(security_drv, qemud_drv->caps);
}



/**
 * qemudStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
qemudStartup(int privileged) {
    char *base = NULL;
    char driverConf[PATH_MAX];
    int rc;

    if (VIR_ALLOC(qemu_driver) < 0)
        return -1;

    if (virMutexInit(&qemu_driver->lock) < 0) {
        VIR_ERROR("%s", _("cannot initialize mutex"));
        VIR_FREE(qemu_driver);
        return -1;
    }
    qemuDriverLock(qemu_driver);
    qemu_driver->privileged = privileged;

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

    if (privileged) {
        if (virAsprintf(&qemu_driver->logDir,
                        "%s/log/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;

        if (virAsprintf(&qemu_driver->stateDir,
                      "%s/run/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if (virAsprintf(&qemu_driver->libDir,
                      "%s/lib/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if (virAsprintf(&qemu_driver->cacheDir,
                      "%s/cache/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;
    } else {
        uid_t uid = geteuid();
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
        if (virAsprintf(&qemu_driver->libDir, "%s/qemu/lib", base) == -1)
            goto out_of_memory;
        if (virAsprintf(&qemu_driver->cacheDir, "%s/qemu/cache", base) == -1)
            goto out_of_memory;
    }

    if (virFileMakePath(qemu_driver->stateDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create state dir '%s': %s\n"),
                  qemu_driver->stateDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->libDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create lib dir '%s': %s\n"),
                  qemu_driver->libDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->cacheDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create cache dir '%s': %s\n"),
                  qemu_driver->cacheDir, virStrerror(errno, ebuf, sizeof ebuf));
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

    rc = virCgroupForDriver("qemu", &qemu_driver->cgroup, privileged, 1);
    if (rc < 0) {
        char buf[1024];
        VIR_WARN("Unable to create cgroup for driver: %s",
                 virStrerror(-rc, buf, sizeof(buf)));
    }

    if ((qemu_driver->caps = qemudCapsInit(NULL)) == NULL)
        goto out_of_memory;

    if ((qemu_driver->activePciHostdevs = pciDeviceListNew(NULL)) == NULL)
        goto error;

    if (qemudLoadDriverConfig(qemu_driver, driverConf) < 0) {
        goto error;
    }

    if (privileged) {
        if (chown(qemu_driver->libDir, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(NULL, errno,
                                 _("unable to set ownership of '%s' to user %d:%d"),
                                 qemu_driver->libDir, qemu_driver->user, qemu_driver->group);
            goto error;
        }
        if (chown(qemu_driver->cacheDir, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(NULL, errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 qemu_driver->cacheDir, qemu_driver->user, qemu_driver->group);
            goto error;
        }
    }

    if (qemudSecurityInit(qemu_driver) < 0) {
        goto error;
    }

    /* If hugetlbfs is present, then we need to create a sub-directory within
     * it, since we can't assume the root mount point has permissions that
     * will let our spawned QEMU instances use it.
     *
     * NB the check for '/', since user may config "" to disable hugepages
     * even when mounted
     */
    if (qemu_driver->hugetlbfs_mount &&
        qemu_driver->hugetlbfs_mount[0] == '/') {
        char *mempath = NULL;
        if (virAsprintf(&mempath, "%s/libvirt/qemu", qemu_driver->hugetlbfs_mount) < 0)
            goto out_of_memory;

        if ((rc = virFileMakePath(mempath)) != 0) {
            virReportSystemError(NULL, rc,
                                 _("unable to create hugepage path %s"), mempath);
            VIR_FREE(mempath);
            goto error;
        }
        if (qemu_driver->privileged &&
            chown(mempath, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(NULL, errno,
                                 _("unable to set ownership on %s to %d:%d"),
                                 mempath, qemu_driver->user, qemu_driver->group);
            VIR_FREE(mempath);
            goto error;
        }

        qemu_driver->hugepage_path = mempath;
    }

    /* Get all the running persistent or transient configs first */
    if (virDomainLoadAllConfigs(NULL,
                                qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->stateDir,
                                NULL,
                                1, NULL, NULL) < 0)
        goto error;

    qemuReconnectDomains(qemu_driver);

    /* Then inactive persistent configs */
    if (virDomainLoadAllConfigs(NULL,
                                qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->configDir,
                                qemu_driver->autostartDir,
                                0, NULL, NULL) < 0)
        goto error;
    qemuDriverUnlock(qemu_driver);

    qemudAutostartConfigs(qemu_driver);


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
                            0, qemudNotifyLoadDomain, qemu_driver);
    qemuDriverUnlock(qemu_driver);

    qemudAutostartConfigs(qemu_driver);

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
    pciDeviceListFree(NULL, qemu_driver->activePciHostdevs);
    virCapabilitiesFree(qemu_driver->caps);

    virDomainObjListFree(&qemu_driver->domains);

    VIR_FREE(qemu_driver->securityDriverName);
    VIR_FREE(qemu_driver->logDir);
    VIR_FREE(qemu_driver->configDir);
    VIR_FREE(qemu_driver->autostartDir);
    VIR_FREE(qemu_driver->stateDir);
    VIR_FREE(qemu_driver->libDir);
    VIR_FREE(qemu_driver->cacheDir);
    VIR_FREE(qemu_driver->vncTLSx509certdir);
    VIR_FREE(qemu_driver->vncListen);
    VIR_FREE(qemu_driver->vncPassword);
    VIR_FREE(qemu_driver->vncSASLdir);
    VIR_FREE(qemu_driver->saveImageFormat);
    VIR_FREE(qemu_driver->hugetlbfs_mount);
    VIR_FREE(qemu_driver->hugepage_path);

    /* Free domain callback list */
    virDomainEventCallbackListFree(qemu_driver->domainEventCallbacks);
    virDomainEventQueueFree(qemu_driver->domainEventQueue);

    if (qemu_driver->domainEventTimer != -1)
        virEventRemoveTimeout(qemu_driver->domainEventTimer);

    if (qemu_driver->brctl)
        brShutdown(qemu_driver->brctl);

    virCgroupFree(&qemu_driver->cgroup);

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
    int retries = (timeout*10);
    int got = 0;
    buf[0] = '\0';

    while (retries) {
        ssize_t func_ret, ret;
        int isdead = 0;

        func_ret = func(conn, vm, buf, fd);

        if (kill(vm->pid, 0) == -1 && errno == ESRCH)
            isdead = 1;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        ret = saferead(fd, buf+got, buflen-got-1);
        if (ret < 0) {
            virReportSystemError(conn, errno,
                                 _("Failure while reading %s log output"),
                                 what);
            return -1;
        }

        got += ret;
        buf[got] = '\0';
        if (got == buflen-1) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Out of space while reading %s log output"),
                             what);
            return -1;
        }

        if (isdead) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Process exited while reading %s log output"),
                             what);
            return -1;
        }

        if (func_ret <= 0)
            return func_ret;

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

static int
qemudOpenMonitorCommon(virConnectPtr conn,
                       struct qemud_driver* driver,
                       virDomainObjPtr vm,
                       int monfd,
                       int reconnect)
{
    char buf[1024];
    int ret;

    if (virSetCloseExec(monfd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to set monitor close-on-exec flag"));
        return -1;
    }
    if (virSetNonBlock(monfd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to put monitor into non-blocking mode"));
        return -1;
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
        return ret;

    if ((vm->monitorWatch = virEventAddHandle(vm->monitor,
                                              VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR,
                                              qemudDispatchVMEvent,
                                              driver, NULL)) < 0)
        return -1;

    return 0;
}

static int
qemudOpenMonitorUnix(virConnectPtr conn,
                     struct qemud_driver* driver,
                     virDomainObjPtr vm,
                     const char *monitor,
                     int reconnect)
{
    struct sockaddr_un addr;
    int monfd;
    int timeout = 3; /* In seconds */
    int ret, i = 0;

    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(conn, errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Monitor path %s too big for destination"), monitor);
        goto error;
    }

    do {
        ret = connect(monfd, (struct sockaddr *) &addr, sizeof(addr));

        if (ret == 0)
            break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        virReportSystemError(conn, errno, "%s",
                             _("failed to connect to monitor socket"));
        goto error;

    } while ((++i <= timeout*5) && (usleep(.2 * 1000000) <= 0));

    if (ret != 0) {
        virReportSystemError(conn, errno, "%s",
                             _("monitor socket did not show up."));
        goto error;
    }

    if (qemudOpenMonitorCommon(conn, driver, vm, monfd, reconnect) < 0)
        goto error;

    return 0;

error:
    close(monfd);
    return -1;
}

static int
qemudOpenMonitorPty(virConnectPtr conn,
                    struct qemud_driver* driver,
                    virDomainObjPtr vm,
                    const char *monitor,
                    int reconnect)
{
    int monfd;

    if ((monfd = open(monitor, O_RDWR)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unable to open monitor path %s"), monitor);
        return -1;
    }

    if (qemudOpenMonitorCommon(conn, driver, vm, monfd, reconnect) < 0)
        goto error;

    return 0;

error:
    close(monfd);
    return -1;
}

static int
qemudOpenMonitor(virConnectPtr conn,
                 struct qemud_driver *driver,
                 virDomainObjPtr vm,
                 int reconnect)
{
    switch (vm->monitor_chr->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        return qemudOpenMonitorUnix(conn, driver, vm,
                                    vm->monitor_chr->data.nix.path,
                                    reconnect);
    case VIR_DOMAIN_CHR_TYPE_PTY:
        return qemudOpenMonitorPty(conn, driver, vm,
                                   vm->monitor_chr->data.file.path,
                                   reconnect);
    default:
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unable to handle monitor type: %s"),
                         virDomainChrTypeToString(vm->monitor_chr->type));
        return -1;
    }
}

/* Returns -1 for error, 0 success, 1 continue reading */
static int
qemudExtractMonitorPath(virConnectPtr conn,
                        const char *haystack,
                        size_t *offset,
                        char **path)
{
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
            *path = strndup(dev, tmp-dev);
            if (*path == NULL) {
                virReportOOMError(conn);
                return -1;
            }

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
    size_t offset = 0;
    int ret, i;

    /* The order in which QEMU prints out the PTY paths is
       the order in which it procsses its serial and parallel
       device args. This code must match that ordering.... */

    /* first comes the serial devices */
    for (i = 0 ; i < vm->def->nserials ; i++) {
        virDomainChrDefPtr chr = vm->def->serials[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                return ret;
        }
    }

    /* then the parallel devices */
    for (i = 0 ; i < vm->def->nparallels ; i++) {
        virDomainChrDefPtr chr = vm->def->parallels[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                return ret;
        }
    }

    return 0;
}

static int
qemudWaitForMonitor(virConnectPtr conn,
                    struct qemud_driver* driver,
                    virDomainObjPtr vm, off_t pos)
{
    char buf[4096]; /* Plenty of space to get startup greeting */
    int logfd;
    int ret;

    if ((logfd = qemudLogReadFD(conn, driver->logDir, vm->def->name, pos))
        < 0)
        return -1;

    ret = qemudReadLogOutput(conn, vm, logfd, buf, sizeof(buf),
                             qemudFindCharDevicePTYs,
                             "console", 3);
    if (close(logfd) < 0) {
        char ebuf[4096];
        VIR_WARN(_("Unable to close logfile: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    if (ret < 0) {
        /* Unexpected end of file - inform user of QEMU log data */
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unable to start guest: %s"), buf);
        return -1;
    }

    if (qemudOpenMonitor(conn, driver, vm, 0) < 0)
        return -1;

    return 0;
}

static int
qemuDetectVcpuPIDs(virConnectPtr conn,
                   virDomainObjPtr vm) {
    pid_t *cpupids = NULL;
    int ncpupids;

    if (vm->def->virtType != VIR_DOMAIN_VIRT_KVM) {
        vm->nvcpupids = 1;
        if (VIR_ALLOC_N(vm->vcpupids, vm->nvcpupids) < 0) {
            virReportOOMError(conn);
            return -1;
        }
        vm->vcpupids[0] = vm->pid;
        return 0;
    }

    /* What follows is now all KVM specific */

    if ((ncpupids = qemuMonitorGetCPUInfo(vm, &cpupids)) < 0)
        return -1;

    /* Treat failure to get VCPU<->PID mapping as non-fatal */
    if (ncpupids == 0)
        return 0;

    if (ncpupids != vm->def->vcpus) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("got wrong number of vCPU pids from QEMU monitor. got %d, wanted %d"),
                         ncpupids, (int)vm->def->vcpus);
        VIR_FREE(cpupids);
        return -1;
    }

    vm->nvcpupids = ncpupids;
    vm->vcpupids = cpupids;
    return 0;
}

static int
qemudInitCpus(virConnectPtr conn,
              virDomainObjPtr vm,
              const char *migrateFrom) {
#if HAVE_SCHED_GETAFFINITY
    cpu_set_t mask;
    int i, maxcpu = QEMUD_CPUMASK_LEN;
    virNodeInfo nodeinfo;

    if (nodeGetInfo(conn, &nodeinfo) < 0)
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
        if (qemuMonitorStartCPUs(conn, vm) < 0) {
            if (virGetLastError() == NULL)
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("resume operation failed"));
            return -1;
        }
    }

    return 0;
}


static int
qemuInitPasswords(struct qemud_driver *driver,
                  virDomainObjPtr vm) {
    int ret = 0;

    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        (vm->def->graphics[0]->data.vnc.passwd || driver->vncPassword)) {

        ret = qemuMonitorSetVNCPassword(vm,
                                        vm->def->graphics[0]->data.vnc.passwd ?
                                        vm->def->graphics[0]->data.vnc.passwd :
                                        driver->vncPassword);
    }

    return ret;
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

static pciDeviceList *
qemuGetPciHostDeviceList(virConnectPtr conn,
                         virDomainDefPtr def)
{
    pciDeviceList *list;
    int i;

    if (!(list = pciDeviceListNew(conn)))
        return NULL;

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
        if (!dev) {
            pciDeviceListFree(conn, list);
            return NULL;
        }

        if (pciDeviceListAdd(conn, list, dev) < 0) {
            pciFreeDevice(conn, dev);
            pciDeviceListFree(conn, list);
            return NULL;
        }

        pciDeviceSetManaged(dev, hostdev->managed);
    }

    return list;
}

static int
qemuUpdateActivePciHostdevs(struct qemud_driver *driver,
                            virDomainDefPtr def)
{
    pciDeviceList *pcidevs;
    int i, ret;

    if (!def->nhostdevs)
        return 0;

    if (!(pcidevs = qemuGetPciHostDeviceList(NULL, def)))
        return -1;

    ret = 0;

    for (i = 0; i < pcidevs->count; i++) {
        if (pciDeviceListAdd(NULL,
                             driver->activePciHostdevs,
                             pcidevs->devs[i]) < 0) {
            ret = -1;
            break;
        }
        pcidevs->devs[i] = NULL;
    }

    pciDeviceListFree(NULL, pcidevs);
    return ret;
}

static int
qemuPrepareHostDevices(virConnectPtr conn,
                       struct qemud_driver *driver,
                       virDomainDefPtr def)
{
    pciDeviceList *pcidevs;
    int i;

    if (!def->nhostdevs)
        return 0;

    if (!(pcidevs = qemuGetPciHostDeviceList(conn, def)))
        return -1;

    /* We have to use 3 loops here. *All* devices must
     * be detached before we reset any of them, because
     * in some cases you have to reset the whole PCI,
     * which impacts all devices on it. Also, all devices
     * must be reset before being marked as active.
     */

    /* XXX validate that non-managed device isn't in use, eg
     * by checking that device is either un-bound, or bound
     * to pci-stub.ko
     */

    for (i = 0; i < pcidevs->count; i++)
        if (pciDeviceGetManaged(pcidevs->devs[i]) &&
            pciDettachDevice(conn, pcidevs->devs[i]) < 0)
            goto error;

    /* Now that all the PCI hostdevs have be dettached, we can safely
     * reset them */
    for (i = 0; i < pcidevs->count; i++)
        if (pciResetDevice(conn, pcidevs->devs[i],
                           driver->activePciHostdevs) < 0)
            goto error;

    /* Now mark all the devices as active */
    for (i = 0; i < pcidevs->count; i++) {
        if (pciDeviceListAdd(conn,
                             driver->activePciHostdevs,
                             pcidevs->devs[i]) < 0)
            goto error;
        pcidevs->devs[i] = NULL;
    }

    pciDeviceListFree(conn, pcidevs);
    return 0;

error:
    pciDeviceListFree(conn, pcidevs);
    return -1;
}

static void
qemuDomainReAttachHostDevices(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainDefPtr def)
{
    pciDeviceList *pcidevs;
    int i;

    if (!def->nhostdevs)
        return;

    if (!(pcidevs = qemuGetPciHostDeviceList(conn, def))) {
        virErrorPtr err = virGetLastError();
        VIR_ERROR(_("Failed to allocate pciDeviceList: %s\n"),
                  err ? err->message : "");
        virResetError(err);
        return;
    }

    /* Again 3 loops; mark all devices as inactive before reset
     * them and reset all the devices before re-attach */

    for (i = 0; i < pcidevs->count; i++)
        pciDeviceListDel(conn, driver->activePciHostdevs, pcidevs->devs[i]);

    for (i = 0; i < pcidevs->count; i++)
        if (pciResetDevice(conn, pcidevs->devs[i],
                           driver->activePciHostdevs) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to reset PCI device: %s\n"),
                      err ? err->message : "");
            virResetError(err);
        }

    for (i = 0; i < pcidevs->count; i++)
        if (pciDeviceGetManaged(pcidevs->devs[i]) &&
            pciReAttachDevice(conn, pcidevs->devs[i]) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to re-attach PCI device: %s\n"),
                      err ? err->message : "");
            virResetError(err);
        }

    pciDeviceListFree(conn, pcidevs);
}

static const char *const defaultDeviceACL[] = {
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
    "/dev/rtc", "/dev/hpet", "/dev/net/tun",
    NULL,
};
#define DEVICE_PTY_MAJOR 136
#define DEVICE_SND_MAJOR 116

static int qemuSetupCgroup(virConnectPtr conn,
                           struct qemud_driver *driver,
                           virDomainObjPtr vm)
{
    virCgroupPtr cgroup = NULL;
    int rc;
    unsigned int i;
    const char *const *deviceACL =
        driver->cgroupDeviceACL ?
        (const char *const *)driver->cgroupDeviceACL :
        defaultDeviceACL;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 1);
    if (rc != 0) {
        virReportSystemError(conn, -rc,
                             _("Unable to create cgroup for %s"),
                             vm->def->name);
        goto cleanup;
    }

    if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        rc = virCgroupDenyAllDevices(cgroup);
        if (rc != 0) {
            if (rc == -EPERM) {
                VIR_WARN0("Group devices ACL is not accessible, disabling whitelisting");
                goto done;
            }

            virReportSystemError(conn, -rc,
                                 _("Unable to deny all devices for %s"), vm->def->name);
            goto cleanup;
        }

        for (i = 0; i < vm->def->ndisks ; i++) {
            if (vm->def->disks[i]->type != VIR_DOMAIN_DISK_TYPE_BLOCK ||
                vm->def->disks[i]->src == NULL)
                continue;

            rc = virCgroupAllowDevicePath(cgroup,
                                          vm->def->disks[i]->src);
            if (rc != 0) {
                virReportSystemError(conn, -rc,
                                     _("Unable to allow device %s for %s"),
                                     vm->def->disks[i]->src, vm->def->name);
                goto cleanup;
            }
        }

        rc = virCgroupAllowDeviceMajor(cgroup, 'c', DEVICE_PTY_MAJOR);
        if (rc != 0) {
            virReportSystemError(conn, -rc, "%s",
                                 _("unable to allow /dev/pts/ devices"));
            goto cleanup;
        }

        if (vm->def->nsounds) {
            rc = virCgroupAllowDeviceMajor(cgroup, 'c', DEVICE_SND_MAJOR);
            if (rc != 0) {
                virReportSystemError(conn, -rc, "%s",
                                     _("unable to allow /dev/snd/ devices"));
                goto cleanup;
            }
        }

        for (i = 0; deviceACL[i] != NULL ; i++) {
            rc = virCgroupAllowDevicePath(cgroup,
                                          deviceACL[i]);
            if (rc < 0 &&
                rc != -ENOENT) {
                virReportSystemError(conn, -rc,
                                     _("unable to allow device %s"),
                                     deviceACL[i]);
                goto cleanup;
            }
        }
    }

done:
    virCgroupFree(&cgroup);
    return 0;

cleanup:
    if (cgroup) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }
    return -1;
}


static int qemuRemoveCgroup(virConnectPtr conn,
                            struct qemud_driver *driver,
                            virDomainObjPtr vm)
{
    virCgroupPtr cgroup;
    int rc;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0);
    if (rc != 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unable to find cgroup for %s\n"),
                         vm->def->name);
        return rc;
    }

    rc = virCgroupRemove(cgroup);
    virCgroupFree(&cgroup);
    return rc;
}

static int qemuAddToCgroup(struct qemud_driver *driver,
                           virDomainDefPtr def)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rc;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, def->name, &cgroup, 0);
    if (rc != 0) {
        virReportSystemError(NULL, -rc,
                             _("unable to find cgroup for domain %s"),
                             def->name);
        goto cleanup;
    }

    rc = virCgroupAddTask(cgroup, getpid());
    if (rc != 0) {
        virReportSystemError(NULL, -rc,
                             _("unable to add domain %s task %d to cgroup"),
                             def->name, getpid());
        goto cleanup;
    }

    ret = 0;

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}


static int qemudDomainSetSecurityLabel(virConnectPtr conn, struct qemud_driver *driver, virDomainObjPtr vm)
{
    if (vm->def->seclabel.label != NULL)
        if (driver->securityDriver && driver->securityDriver->domainSetSecurityLabel)
            return driver->securityDriver->domainSetSecurityLabel(conn, driver->securityDriver,
                                                                 vm);
    return 0;
}


#ifdef __linux__
struct qemuFileOwner {
    uid_t uid;
    gid_t gid;
};

static int qemuDomainSetHostdevUSBOwnershipActor(virConnectPtr conn,
                                                 usbDevice *dev ATTRIBUTE_UNUSED,
                                                 const char *file, void *opaque)
{
    struct qemuFileOwner *owner = opaque;

    VIR_DEBUG("Setting ownership on %s to %d:%d", file, owner->uid, owner->gid);

    if (chown(file, owner->uid, owner->gid) < 0) {
        virReportSystemError(conn, errno, _("cannot set ownership on %s"), file);
        return -1;
    }

    return 0;
}

static int qemuDomainSetHostdevUSBOwnership(virConnectPtr conn,
                                            virDomainHostdevDefPtr def,
                                            uid_t uid, gid_t gid)
{
    struct qemuFileOwner owner = { uid, gid };
    int ret = -1;

    /* XXX what todo for USB devs assigned based on product/vendor ? Doom :-( */
    if (!def->source.subsys.u.usb.bus ||
        !def->source.subsys.u.usb.device)
        return 0;

    usbDevice *dev = usbGetDevice(conn,
                                  def->source.subsys.u.usb.bus,
                                  def->source.subsys.u.usb.device);

    if (!dev)
        goto cleanup;

    ret = usbDeviceFileIterate(conn, dev,
                               qemuDomainSetHostdevUSBOwnershipActor, &owner);

    usbFreeDevice(conn, dev);
cleanup:
    return ret;
}

static int qemuDomainSetHostdevPCIOwnershipActor(virConnectPtr conn,
                                                 pciDevice *dev ATTRIBUTE_UNUSED,
                                                 const char *file, void *opaque)
{
    struct qemuFileOwner *owner = opaque;

    VIR_DEBUG("Setting ownership on %s to %d:%d", file, owner->uid, owner->gid);

    if (chown(file, owner->uid, owner->gid) < 0) {
        virReportSystemError(conn, errno, _("cannot set ownership on %s"), file);
        return -1;
    }

    return 0;
}

static int qemuDomainSetHostdevPCIOwnership(virConnectPtr conn,
                                            virDomainHostdevDefPtr def,
                                            uid_t uid, gid_t gid)
{
    struct qemuFileOwner owner = { uid, gid };
    int ret = -1;

    pciDevice *dev = pciGetDevice(conn,
                                  def->source.subsys.u.pci.domain,
                                  def->source.subsys.u.pci.bus,
                                  def->source.subsys.u.pci.slot,
                                  def->source.subsys.u.pci.function);

    if (!dev)
        goto cleanup;

    ret = pciDeviceFileIterate(conn, dev,
                               qemuDomainSetHostdevPCIOwnershipActor, &owner);

    pciFreeDevice(conn, dev);
cleanup:
    return ret;
}
#endif


static int qemuDomainSetHostdevOwnership(virConnectPtr conn,
                                         virDomainHostdevDefPtr def,
                                         uid_t uid, gid_t gid)
{
    if (def->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

#ifdef __linux__
    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return qemuDomainSetHostdevUSBOwnership(conn, def, uid, gid);

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        return qemuDomainSetHostdevPCIOwnership(conn, def, uid, gid);

    }
    return 0;
#else
    qemudReportError(conn, NULL, NULL, "%s",
                     _("unable to set host device ownership on this platform"));
    return -1;
#endif

}

static int qemuDomainSetFileOwnership(virConnectPtr conn,
                                      const char *path,
                                      uid_t uid, gid_t gid)
{

    if (!path)
        return 0;

    VIR_DEBUG("Setting ownership on %s to %d:%d", path, uid, gid);
    if (chown(path, uid, gid) < 0) {
        virReportSystemError(conn, errno, _("cannot set ownership on %s"),
                             path);
        return -1;
    }
    return 0;
}

static int qemuDomainSetDeviceOwnership(virConnectPtr conn,
                                        struct qemud_driver *driver,
                                        virDomainDeviceDefPtr def,
                                        int restore)
{
    uid_t uid;
    gid_t gid;

    if (!driver->privileged)
        return 0;

    /* short circuit case of root:root */
    if (!driver->user && !driver->group)
        return 0;

    uid = restore ? 0 : driver->user;
    gid = restore ? 0 : driver->group;

    switch (def->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (restore &&
            (def->data.disk->readonly || def->data.disk->shared))
            return 0;

        return qemuDomainSetFileOwnership(conn, def->data.disk->src, uid, gid);

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        return qemuDomainSetHostdevOwnership(conn, def->data.hostdev, uid, gid);
    }

    return 0;
}

static int qemuDomainSetAllDeviceOwnership(virConnectPtr conn,
                                           struct qemud_driver *driver,
                                           virDomainDefPtr def,
                                           int restore)
{
    int i;
    uid_t uid;
    gid_t gid;

    if (!driver->privileged)
        return 0;

    /* short circuit case of root:root */
    if (!driver->user && !driver->group)
        return 0;

    uid = restore ? 0 : driver->user;
    gid = restore ? 0 : driver->group;

    if (qemuDomainSetFileOwnership(conn, def->os.kernel, uid, gid) < 0 ||
        qemuDomainSetFileOwnership(conn, def->os.initrd, uid, gid) < 0)
        return -1;

    for (i = 0 ; i < def->ndisks ; i++) {
        if (restore &&
            (def->disks[i]->readonly || def->disks[i]->shared))
            continue;

        if (qemuDomainSetFileOwnership(conn, def->disks[i]->src, uid, gid) < 0)
            return -1;
    }

    for (i = 0 ; i < def->nhostdevs ; i++) {
        if (qemuDomainSetHostdevOwnership(conn, def->hostdevs[i], uid, gid) < 0)
            return -1;
    }

    return 0;
}

static virDomainPtr qemudDomainLookupByName(virConnectPtr conn,
                                            const char *name);

struct qemudHookData {
    virConnectPtr conn;
    virDomainObjPtr vm;
    struct qemud_driver *driver;
};

static int qemudSecurityHook(void *data) {
    struct qemudHookData *h = data;

    if (qemuAddToCgroup(h->driver, h->vm->def) < 0)
        return -1;

    if (qemudDomainSetSecurityLabel(h->conn, h->driver, h->vm) < 0)
        return -1;

    if (h->driver->privileged) {
        if (qemuDomainSetAllDeviceOwnership(h->conn, h->driver, h->vm->def, 0) < 0)
            return -1;

        DEBUG("Dropping privileges of VM to %d:%d", h->driver->user, h->driver->group);

        if (h->driver->group) {
            if (setregid(h->driver->group, h->driver->group) < 0) {
                virReportSystemError(NULL, errno,
                                     _("cannot change to '%d' group"),
                                     h->driver->group);
                return -1;
            }
        }
        if (h->driver->user) {
            if (setreuid(h->driver->user, h->driver->user) < 0) {
                virReportSystemError(NULL, errno,
                                     _("cannot change to '%d' user"),
                                     h->driver->user);
                return -1;
            }
        }
    }

    return 0;
}

static int
qemuPrepareMonitorChr(virConnectPtr conn,
                      struct qemud_driver *driver,
                      virDomainChrDefPtr monitor_chr,
                      const char *vm)
{
    monitor_chr->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monitor_chr->data.nix.listen = 1;

    if (virAsprintf(&monitor_chr->data.nix.path, "%s/%s.monitor",
                    driver->libDir, vm) < 0) {
        virReportOOMError(conn);
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
    char *pidfile = NULL;
    int logfile;

    struct qemudHookData hookData;
    hookData.conn = conn;
    hookData.vm = vm;
    hookData.driver = driver;

    FD_ZERO(&keepfd);

    if (virDomainIsActive(vm)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("VM is already active"));
        return -1;
    }

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        driver->securityDriver &&
        driver->securityDriver->domainGenSecurityLabel &&
        driver->securityDriver->domainGenSecurityLabel(conn, vm) < 0)
        return -1;

    /* Ensure no historical cgroup for this VM is lieing around bogus settings */
    qemuRemoveCgroup(conn, driver, vm);

    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport) {
        int port = qemudNextFreeVNCPort(driver);
        if (port < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Unable to find an unused VNC port"));
            goto cleanup;
        }
        vm->def->graphics[0]->data.vnc.port = port;
    }

    if (virFileMakePath(driver->logDir) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot create log directory %s"),
                             driver->logDir);
        goto cleanup;
    }

    if ((logfile = qemudLogFD(conn, driver, vm->def->name)) < 0)
        goto cleanup;

    emulator = vm->def->emulator;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so its hard to feed back a useful error
     */
    if (stat(emulator, &sb) < 0) {
        virReportSystemError(conn, errno,
                             _("Cannot find QEMU binary %s"),
                             emulator);
        goto cleanup;
    }

    if (qemudExtractVersionInfo(emulator,
                                NULL,
                                &qemuCmdFlags) < 0)
        goto cleanup;

    if (qemuSetupCgroup(conn, driver, vm) < 0)
        goto cleanup;

    if (qemuPrepareHostDevices(conn, driver, vm->def) < 0)
        goto cleanup;

    if (VIR_ALLOC(vm->monitor_chr) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (qemuPrepareMonitorChr(conn, driver, vm->monitor_chr, vm->def->name) < 0)
        goto cleanup;

    if ((ret = virFileDeletePid(driver->stateDir, vm->def->name)) != 0) {
        virReportSystemError(conn, ret,
                             _("Cannot remove stale PID file for %s"),
                             vm->def->name);
        goto cleanup;
    }

    if (!(pidfile = virFilePid(driver->stateDir, vm->def->name))) {
        virReportSystemError(conn, errno,
                             "%s", _("Failed to build pidfile path."));
        goto cleanup;
    }

    vm->def->id = driver->nextvmid++;
    if (qemudBuildCommandLine(conn, driver, vm->def, vm->monitor_chr,
                              qemuCmdFlags, &argv, &progenv,
                              &tapfds, &ntapfds, migrateFrom) < 0)
        goto cleanup;

    tmp = progenv;
    while (*tmp) {
        if (safewrite(logfile, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(logfile, " ", 1) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    tmp = argv;
    while (*tmp) {
        if (safewrite(logfile, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(logfile, " ", 1) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s\n"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    if (safewrite(logfile, "\n", 1) < 0)
        VIR_WARN(_("Unable to write argv to logfile: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));

    if ((pos = lseek(logfile, 0, SEEK_END)) < 0)
        VIR_WARN(_("Unable to seek to end of logfile: %s\n"),
                 virStrerror(errno, ebuf, sizeof ebuf));

    for (i = 0 ; i < ntapfds ; i++)
        FD_SET(tapfds[i], &keepfd);

    ret = virExecDaemonize(conn, argv, progenv, &keepfd, &child,
                           stdin_fd, &logfile, &logfile,
                           VIR_EXEC_NONBLOCK | VIR_EXEC_CLEAR_CAPS,
                           qemudSecurityHook, &hookData,
                           pidfile);
    VIR_FREE(pidfile);

    /* wait for qemu process to to show up */
    if (ret == 0) {
        if (virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Domain %s didn't show up\n"), vm->def->name);
            ret = -1;
        }
    } else if (ret == -2) {
        /* The virExec process that launches the daemon failed. Pending on
         * when it failed (we can't determine for sure), there may be
         * extra info in the domain log (if the hook failed for example).
         *
         * Pretend like things succeeded, and let 'WaitForMonitor' report
         * the log contents for us.
         */
        vm->pid = child;
        ret = 0;
    }

    vm->state = migrateFrom ? VIR_DOMAIN_PAUSED : VIR_DOMAIN_RUNNING;

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

    if (ret == -1)
        goto cleanup;

    if ((qemudWaitForMonitor(conn, driver, vm, pos) < 0) ||
        (qemuDetectVcpuPIDs(conn, vm) < 0) ||
        (qemudInitCpus(conn, vm, migrateFrom) < 0) ||
        (qemuInitPasswords(driver, vm) < 0) ||
        (qemuMonitorSetBalloon(vm, vm->def->memory) < 0) ||
        (virDomainSaveStatus(conn, driver->stateDir, vm) < 0)) {
        qemudShutdownVMDaemon(conn, driver, vm);
        ret = -1;
        /* No need for 'goto cleanup' now since qemudShutdownVMDaemon does enough */
    }

    if (logfile != -1)
        close(logfile);

    return ret;

cleanup:
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        VIR_FREE(vm->def->seclabel.model);
        VIR_FREE(vm->def->seclabel.label);
        VIR_FREE(vm->def->seclabel.imagelabel);
    }
    qemuRemoveCgroup(conn, driver, vm);
    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport)
        vm->def->graphics[0]->data.vnc.port = -1;
    if (logfile != -1)
        close(logfile);
    vm->def->id = -1;
    return -1;
}


static void qemudShutdownVMDaemon(virConnectPtr conn,
                                  struct qemud_driver *driver,
                                  virDomainObjPtr vm) {
    int ret;
    int retries = 0;

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

    if (vm->monitor != -1)
        close(vm->monitor);
    vm->monitor = -1;

    if (vm->monitor_chr) {
        if (vm->monitor_chr->type == VIR_DOMAIN_CHR_TYPE_UNIX)
            unlink(vm->monitor_chr->data.nix.path);
        virDomainChrDefFree(vm->monitor_chr);
        vm->monitor_chr = NULL;
    }

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

    if (qemuDomainSetAllDeviceOwnership(conn, driver, vm->def, 1) < 0)
        VIR_WARN("Failed to restore all device ownership for %s",
                 vm->def->name);

    qemuDomainReAttachHostDevices(conn, driver, vm->def);

retry:
    if ((ret = qemuRemoveCgroup(conn, driver, vm)) < 0) {
        if (ret == -EBUSY && (retries++ < 5)) {
            usleep(200*1000);
            goto retry;
        }
        VIR_WARN("Failed to remove cgroup for %s",
                 vm->def->name);
    }

    if (qemudRemoveDomainStatus(conn, driver, vm) < 0) {
        VIR_WARN(_("Failed to remove domain status for %s"),
                 vm->def->name);
    }
    if ((ret = virFileDeletePid(driver->stateDir, vm->def->name)) != 0) {
        char ebuf[1024];
        VIR_WARN(_("Failed to remove PID file for %s: %s"),
                 vm->def->name, virStrerror(errno, ebuf, sizeof ebuf));
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



static virDrvOpenStatus qemudOpen(virConnectPtr conn,
                                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                  int flags ATTRIBUTE_UNUSED) {
    if (conn->uri == NULL) {
        if (qemu_driver == NULL)
            return VIR_DRV_OPEN_DECLINED;

        conn->uri = xmlParseURI(qemu_driver->privileged ?
                                "qemu:///system" :
                                "qemu:///session");
        if (!conn->uri) {
            virReportOOMError(conn);
            return VIR_DRV_OPEN_ERROR;
        }
    } else {
        /* If URI isn't 'qemu' its definitely not for us */
        if (conn->uri->scheme == NULL ||
            STRNEQ(conn->uri->scheme, "qemu"))
            return VIR_DRV_OPEN_DECLINED;

        /* Allow remote driver to deal with URIs with hostname server */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        if (qemu_driver == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("qemu state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }

        if (qemu_driver->privileged) {
            if (STRNEQ (conn->uri->path, "/system") &&
                STRNEQ (conn->uri->path, "/session")) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unexpected QEMU URI path '%s', try qemu:///system"),
                                 conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }
        } else {
            if (STRNEQ (conn->uri->path, "/session")) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unexpected QEMU URI path '%s', try qemu:///session"),
                                 conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }
        }
    }
    conn->privateData = qemu_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int qemudClose(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;

    /* Get rid of callbacks registered for this conn */
    qemuDriverLock(driver);
    virDomainEventCallbackListRemoveConn(conn, driver->domainEventCallbacks);
    qemuDriverUnlock(driver);

    conn->privateData = NULL;

    return 0;
}

/* Which features are supported by this driver? */
static int
qemudSupportsFeature (virConnectPtr conn ATTRIBUTE_UNUSED, int feature)
{
    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
        return 1;
    default:
        return 0;
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


static char *qemudGetCapabilities(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;
    virCapsPtr caps;
    char *xml = NULL;

    qemuDriverLock(driver);
    if ((caps = qemudCapsInit(qemu_driver->caps)) == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (qemu_driver->securityDriver &&
        qemudSecurityCapsInit(qemu_driver->securityDriver, caps) < 0) {
        virCapabilitiesFree(caps);
        virReportOOMError(conn);
        goto cleanup;
    }

    virCapabilitiesFree(qemu_driver->caps);
    qemu_driver->caps = caps;

    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError(conn);

cleanup:
    qemuDriverUnlock(driver);

    return xml;
}


static int qemudGetProcessInfo(unsigned long long *cpuTime, int *lastCpu, int pid, int tid) {
    char proc[PATH_MAX];
    FILE *pidinfo;
    unsigned long long usertime, systime;
    int cpu;
    int ret;

    if (tid)
        ret = snprintf(proc, sizeof(proc), "/proc/%d/task/%d/stat", pid, tid);
    else
        ret = snprintf(proc, sizeof(proc), "/proc/%d/stat", pid);
    if (ret >= (int)sizeof(proc)) {
        errno = E2BIG;
        return -1;
    }

    if (!(pidinfo = fopen(proc, "r"))) {
        /*printf("cannot read pid info");*/
        /* VM probably shut down, so fake 0 */
        if (cpuTime)
            *cpuTime = 0;
        if (lastCpu)
            *lastCpu = 0;
        return 0;
    }

    /* See 'man proc' for information about what all these fields are. We're
     * only interested in a very few of them */
    if (fscanf(pidinfo,
               /* pid -> stime */
               "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu"
               /* cutime -> endcode */
               "%*d %*d %*d %*d %*d %*u %*u %*d %*u %*u %*u %*u"
               /* startstack -> processor */
               "%*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %d",
               &usertime, &systime, &cpu) != 3) {
        fclose(pidinfo);
        VIR_WARN0("cannot parse process status data");
        errno = -EINVAL;
        return -1;
    }

    /* We got jiffies
     * We want nanoseconds
     * _SC_CLK_TCK is jiffies per second
     * So calulate thus....
     */
    if (cpuTime)
        *cpuTime = 1000ull * 1000ull * 1000ull * (usertime + systime) / (unsigned long long)sysconf(_SC_CLK_TCK);
    if (lastCpu)
        *lastCpu = cpu;


    VIR_DEBUG("Got status for %d/%d user=%llu sys=%llu cpu=%d",
              pid, tid, usertime, systime, cpu);

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
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching id %d"), id);
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
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
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching name '%s'"), name);
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

    if (virSecurityDriverVerify(conn, def) < 0)
        goto cleanup;

    /* See if a VM with matching UUID already exists */
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
    if (vm) {
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(vm->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain '%s' is already defined with uuid %s"),
                             vm->def->name, uuidstr);
            goto cleanup;
        }

        /* UUID & name match, but if VM is already active, refuse it */
        if (virDomainIsActive(vm)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain is already active as '%s'"), vm->def->name);
            goto cleanup;
        }
        virDomainObjUnlock(vm);
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        vm = virDomainFindByName(&driver->domains, def->name);
        if (vm) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain '%s' is already defined with uuid %s"),
                             def->name, uuidstr);
            goto cleanup;
        }
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
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto cleanup;
    }
    if (vm->state != VIR_DOMAIN_PAUSED) {
        if (qemuMonitorStopCPUs(vm) < 0)
            goto cleanup;
        vm->state = VIR_DOMAIN_PAUSED;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }
    if (virDomainSaveStatus(dom->conn, driver->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);

    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


static int qemudDomainResume(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto cleanup;
    }
    if (vm->state == VIR_DOMAIN_PAUSED) {
        if (qemuMonitorStartCPUs(dom->conn, vm) < 0) {
            if (virGetLastError() == NULL)
                qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                                 "%s", _("resume operation failed"));
            goto cleanup;
        }
        vm->state = VIR_DOMAIN_RUNNING;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }
    if (virDomainSaveStatus(dom->conn, driver->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


static int qemudDomainShutdown(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto cleanup;
    }

    if (qemuMonitorSystemPowerdown(vm) < 0)
        goto cleanup;

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
    vm  = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
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
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
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
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
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
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (newmem > vm->def->maxmem) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set memory higher than max memory"));
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        int r = qemuMonitorSetBalloon(vm, newmem);
        if (r < 0)
            goto cleanup;

        /* Lack of balloon support is a fatal error */
        if (r == 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                             "%s", _("cannot set memory of an active domain"));
            goto cleanup;
        }
    } else {
        vm->def->memory = newmem;
    }
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
    int err;
    unsigned long balloon;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (qemudGetProcessInfo(&(info->cpuTime), NULL, vm->pid, 0) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, ("cannot read cputime for domain"));
            goto cleanup;
        }
    }

    info->maxMem = vm->def->maxmem;

    if (virDomainIsActive(vm)) {
        err = qemuMonitorGetBalloonInfo(vm, &balloon);
        if (err < 0)
            goto cleanup;

        if (err == 0)
            /* Balloon not supported, so maxmem is always the allocation */
            info->memory = vm->def->maxmem;
        else
            info->memory = balloon;
    } else {
        info->memory = vm->def->memory;
    }

    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


#define QEMUD_SAVE_MAGIC "LibvirtQemudSave"
#define QEMUD_SAVE_VERSION 2

enum qemud_save_formats {
    QEMUD_SAVE_FORMAT_RAW = 0,
    QEMUD_SAVE_FORMAT_GZIP = 1,
    QEMUD_SAVE_FORMAT_BZIP2 = 2,
    /*
     * Deprecated by xz and never used as part of a release
     * QEMUD_SAVE_FORMAT_LZMA
     */
    QEMUD_SAVE_FORMAT_XZ = 3,
    QEMUD_SAVE_FORMAT_LZOP = 4,
    /* Note: add new members only at the end.
       These values are used in the on-disk format.
       Do not change or re-use numbers. */

    QEMUD_SAVE_FORMAT_LAST
};

VIR_ENUM_DECL(qemudSaveCompression)
VIR_ENUM_IMPL(qemudSaveCompression, QEMUD_SAVE_FORMAT_LAST,
              "raw",
              "gzip",
              "bzip2",
              "xz",
              "lzop")

struct qemud_save_header {
    char magic[sizeof(QEMUD_SAVE_MAGIC)-1];
    int version;
    int xml_len;
    int was_running;
    int compressed;
    int unused[15];
};

static int qemudDomainSave(virDomainPtr dom,
                           const char *path)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int fd = -1;
    char *xml = NULL;
    struct qemud_save_header header;
    int ret = -1;
    virDomainEventPtr event = NULL;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic));
    header.version = QEMUD_SAVE_VERSION;

    qemuDriverLock(driver);
    if (driver->saveImageFormat == NULL)
        header.compressed = QEMUD_SAVE_FORMAT_RAW;
    else {
        header.compressed =
            qemudSaveCompressionTypeFromString(driver->saveImageFormat);
        if (header.compressed < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("Invalid save image format specified "
                                     "in configuration file"));
            goto cleanup;
        }
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto cleanup;
    }

    /* Pause */
    if (vm->state == VIR_DOMAIN_RUNNING) {
        header.was_running = 1;
        if (qemuMonitorStopCPUs(vm) < 0)
            goto cleanup;
        vm->state = VIR_DOMAIN_PAUSED;
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

    if (header.compressed == QEMUD_SAVE_FORMAT_RAW) {
        const char *args[] = { "cat", NULL };
        ret = qemuMonitorMigrateToCommand(vm, 0, args, path);
    } else {
        const char *prog = qemudSaveCompressionTypeToString(header.compressed);
        const char *args[] = {
            prog,
            "-c",
            NULL
        };
        ret = qemuMonitorMigrateToCommand(vm, 0, args, path);
    }

    if (ret < 0)
        goto cleanup;

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

cleanup:
    if (fd != -1)
        close(fd);
    VIR_FREE(xml);
    if (ret != 0)
        unlink(path);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


static int qemudDomainCoreDump(virDomainPtr dom,
                               const char *path,
                               int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int resume = 0, paused = 0;
    int ret = -1;
    const char *args[] = {
        "cat",
        NULL,
    };

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto cleanup;
    }

    /* Migrate will always stop the VM, so once we support live dumping
       the resume condition will stay the same, independent of whether
       the stop command is issued.  */
    resume = (vm->state == VIR_DOMAIN_RUNNING);

    /* Pause domain for non-live dump */
    if (vm->state == VIR_DOMAIN_RUNNING) {
        if (qemuMonitorStopCPUs(vm) < 0)
            goto cleanup;
        paused = 1;
    }

    ret = qemuMonitorMigrateToCommand(vm, 0, args, path);
    paused = 1;
cleanup:

    /* Since the monitor is always attached to a pty for libvirt, it
       will support synchronous operations so we always get here after
       the migration is complete.  */
    if (resume && paused) {
        if (qemuMonitorStartCPUs(dom->conn, vm) < 0) {
            if (virGetLastError() == NULL)
                qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                                 "%s", _("resuming after dump failed"));
        }
    }
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int qemudDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int max;
    int ret = -1;
    const char *type;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID, "%s",
                         _("cannot change vcpu count of an active domain"));
        goto cleanup;
    }

    if (!(type = virDomainVirtTypeToString(vm->def->virtType))) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unknown virt type in domain definition '%d'"),
                         vm->def->virtType);
        goto cleanup;
    }

    if ((max = qemudGetMaxVCPUs(dom->conn, type)) < 0) {
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

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s",_("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    if (vcpu > (vm->nvcpupids-1)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         _("vcpu number out of range %d > %d"),
                         vcpu, vm->nvcpupids);
        goto cleanup;
    }

    if (nodeGetInfo(dom->conn, &nodeinfo) < 0)
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

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s",_("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    if (nodeGetInfo(dom->conn, &nodeinfo) < 0)
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

                if (vm->vcpupids != NULL &&
                    qemudGetProcessInfo(&(info[i].cpuTime),
                                        &(info[i].cpu),
                                        vm->pid,
                                        vm->vcpupids[i]) < 0) {
                    virReportSystemError(dom->conn, errno, "%s",
                                         _("cannot get vCPU placement & pCPU time"));
                    goto cleanup;
                }
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
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
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

    memset(seclabel, 0, sizeof(*seclabel));

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
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
                                 "%s", _("Failed to get security label"));
                goto cleanup;
            }
        }
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemudNodeGetSecurityModel(virConnectPtr conn,
                                     virSecurityModelPtr secmodel)
{
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    char *p;
    int ret = 0;

    qemuDriverLock(driver);
    if (!driver->securityDriver) {
        memset(secmodel, 0, sizeof (*secmodel));
        goto cleanup;
    }

    p = driver->caps->host.secModel.model;
    if (strlen(p) >= VIR_SECURITY_MODEL_BUFLEN-1) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("security model string exceeds max %d bytes"),
                         VIR_SECURITY_MODEL_BUFLEN-1);
        ret = -1;
        goto cleanup;
    }
    strcpy(secmodel->model, p);

    p = driver->caps->host.secModel.doi;
    if (strlen(p) >= VIR_SECURITY_DOI_BUFLEN-1) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("security DOI string exceeds max %d bytes"),
                         VIR_SECURITY_DOI_BUFLEN-1);
        ret = -1;
        goto cleanup;
    }
    strcpy(secmodel->doi, p);

cleanup:
    qemuDriverUnlock(driver);
    return ret;
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
    int intermediatefd = -1;
    pid_t intermediate_pid = -1;
    int childstat;

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

    /* See if a VM with matching UUID already exists */
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
    if (vm) {
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(vm->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain '%s' is already defined with uuid %s"),
                             vm->def->name, uuidstr);
            goto cleanup;
        }

        /* UUID & name match, but if VM is already active, refuse it */
        if (virDomainIsActive(vm)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_INVALID,
                             _("domain is already active as '%s'"), vm->def->name);
            goto cleanup;
        }
        virDomainObjUnlock(vm);
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        vm = virDomainFindByName(&driver->domains, def->name);
        if (vm) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain '%s' is already defined with uuid %s"),
                             def->name, uuidstr);
            goto cleanup;
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

    if (header.version == 2) {
        const char *intermediate_argv[3] = { NULL, "-dc", NULL };
        const char *prog = qemudSaveCompressionTypeToString(header.compressed);
        if (prog == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("Invalid compressed save format %d"),
                             header.compressed);
            goto cleanup;
        }

        if (header.compressed != QEMUD_SAVE_FORMAT_RAW) {
            intermediate_argv[0] = prog;
            intermediatefd = fd;
            fd = -1;
            if (virExec(conn, intermediate_argv, NULL, NULL,
                        &intermediate_pid, intermediatefd, &fd, NULL, 0) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Failed to start decompression binary %s"),
                                 intermediate_argv[0]);
                goto cleanup;
            }
        }
    }
    /* Set the migration source and start it up. */
    ret = qemudStartVMDaemon(conn, driver, vm, "stdio", fd);
    if (intermediate_pid != -1) {
        /* Wait for intermediate process to exit */
        while (waitpid(intermediate_pid, &childstat, 0) == -1 &&
               errno == EINTR);
    }
    if (intermediatefd != -1)
        close(intermediatefd);
    close(fd);
    fd = -1;
    if (ret < 0) {
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
        if (qemuMonitorStartCPUs(conn, vm) < 0) {
            if (virGetLastError() == NULL)
                qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                                 "%s", _("failed to resume domain"));
            goto cleanup;
        }
        vm->state = VIR_DOMAIN_RUNNING;
        virDomainSaveStatus(conn, driver->stateDir, vm);
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
    unsigned long balloon;
    int err;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    /* Refresh current memory based on balloon info */
    if (virDomainIsActive(vm)) {
        err = qemuMonitorGetBalloonInfo(vm, &balloon);
        if (err < 0)
            goto cleanup;
        if (err > 0)
            vm->def->memory = balloon;
        /* err == 0 indicates no balloon support, so ignore it */
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


static char *qemuDomainXMLFromNative(virConnectPtr conn,
                                     const char *format,
                                     const char *config,
                                     unsigned int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    char *xml = NULL;

    if (STRNEQ(format, QEMU_CONFIG_FORMAT_ARGV)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INVALID_ARG,
                         _("unsupported config type %s"), format);
        goto cleanup;
    }

    qemuDriverLock(driver);
    def = qemuParseCommandLineString(conn, driver->caps, config);
    qemuDriverUnlock(driver);
    if (!def)
        goto cleanup;

    xml = virDomainDefFormat(conn, def, VIR_DOMAIN_XML_INACTIVE);

cleanup:
    virDomainDefFree(def);
    return xml;
}

static char *qemuDomainXMLToNative(virConnectPtr conn,
                                   const char *format,
                                   const char *xmlData,
                                   unsigned int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainChrDef monitor_chr;
    const char *emulator;
    unsigned int qemuCmdFlags;
    struct stat sb;
    const char **retargv = NULL;
    const char **retenv = NULL;
    const char **tmp;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *ret = NULL;
    int i;

    qemuDriverLock(driver);

    if (STRNEQ(format, QEMU_CONFIG_FORMAT_ARGV)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INVALID_ARG,
                         _("unsupported config type %s"), format);
        goto cleanup;
    }

    def = virDomainDefParseString(conn, driver->caps, xmlData, 0);
    if (!def)
        goto cleanup;

    /* Since we're just exporting args, we can't do bridge/network
     * setups, since libvirt will normally create TAP devices
     * directly. We convert those configs into generic 'ethernet'
     * config and assume the user has suitable 'ifup-qemu' scripts
     */
    for (i = 0 ; i < def->nnets ; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            VIR_FREE(net->data.network.name);

            memset(net, 0, sizeof *net);

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            net->data.ethernet.dev = NULL;
            net->data.ethernet.script = NULL;
            net->data.ethernet.ipaddr = NULL;
        } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            char *brname = net->data.bridge.brname;
            char *script = net->data.bridge.script;
            char *ipaddr = net->data.bridge.ipaddr;

            memset(net, 0, sizeof *net);

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            net->data.ethernet.dev = brname;
            net->data.ethernet.script = script;
            net->data.ethernet.ipaddr = ipaddr;
        }
    }
    for (i = 0 ; i < def->ngraphics ; i++) {
        if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            def->graphics[i]->data.vnc.autoport)
            def->graphics[i]->data.vnc.port = 5900;
    }
    emulator = def->emulator;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so its hard to feed back a useful error
     */
    if (stat(emulator, &sb) < 0) {
        virReportSystemError(conn, errno,
                             _("Cannot find QEMU binary %s"),
                             emulator);
        goto cleanup;
    }

    if (qemudExtractVersionInfo(emulator,
                                NULL,
                                &qemuCmdFlags) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot determine QEMU argv syntax %s"),
                         emulator);
        goto cleanup;
    }

    if (qemuPrepareMonitorChr(conn, driver, &monitor_chr, def->name) < 0)
        goto cleanup;

    if (qemudBuildCommandLine(conn, driver, def,
                              &monitor_chr, qemuCmdFlags,
                              &retargv, &retenv,
                              NULL, NULL, /* Don't want it to create TAP devices */
                              NULL) < 0) {
        goto cleanup;
    }

    tmp = retenv;
    while (*tmp) {
        virBufferAdd(&buf, *tmp, strlen(*tmp));
        virBufferAddLit(&buf, " ");
        tmp++;
    }
    tmp = retargv;
    while (*tmp) {
        virBufferAdd(&buf, *tmp, strlen(*tmp));
        virBufferAddLit(&buf, " ");
        tmp++;
    }

    if (virBufferError(&buf))
        goto cleanup;

    ret = virBufferContentAndReset(&buf);

cleanup:
    qemuDriverUnlock(driver);
    for (tmp = retargv ; tmp && *tmp ; tmp++)
        VIR_FREE(*tmp);
    VIR_FREE(retargv);

    for (tmp = retenv ; tmp && *tmp ; tmp++)
        VIR_FREE(*tmp);
    VIR_FREE(retenv);

    virDomainDefFree(def);
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

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
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
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemudCanonicalizeMachineFromInfo(virDomainDefPtr def,
                                 virCapsGuestDomainInfoPtr info,
                                 char **canonical)
{
    int i;

    *canonical = NULL;

    for (i = 0; i < info->nmachines; i++) {
        virCapsGuestMachinePtr machine = info->machines[i];

        if (!machine->canonical)
            continue;

        if (strcmp(def->os.machine, machine->name) != 0)
            continue;

        if (!(*canonical = strdup(machine->canonical))) {
            virReportOOMError(NULL);
            return -1;
        }

        break;
    }

    return 0;
}

static int
qemudCanonicalizeMachineDirect(virDomainDefPtr def, char **canonical)
{
    virCapsGuestMachinePtr *machines = NULL;
    int i, nmachines = 0;

    if (qemudProbeMachineTypes(def->emulator, &machines, &nmachines) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    for (i = 0; i < nmachines; i++) {
        if (!machines[i]->canonical)
            continue;

        if (strcmp(def->os.machine, machines[i]->name) != 0)
            continue;

        *canonical = machines[i]->canonical;
        machines[i]->canonical = NULL;
        break;
    }

    virCapabilitiesFreeMachines(machines, nmachines);

    return 0;
}

int
qemudCanonicalizeMachine(struct qemud_driver *driver, virDomainDefPtr def)
{
    char *canonical = NULL;
    int i;

    for (i = 0; i < driver->caps->nguests; i++) {
        virCapsGuestPtr guest = driver->caps->guests[i];
        virCapsGuestDomainInfoPtr info;
        int j;

        for (j = 0; j < guest->arch.ndomains; j++) {
            info = &guest->arch.domains[j]->info;

            if (!info->emulator || !STREQ(info->emulator, def->emulator))
                continue;

            if (!info->nmachines)
                info = &guest->arch.defaultInfo;

            if (qemudCanonicalizeMachineFromInfo(def, info, &canonical) < 0)
                return -1;
            goto out;
        }

        info = &guest->arch.defaultInfo;

        if (info->emulator && STREQ(info->emulator, def->emulator)) {
            if (qemudCanonicalizeMachineFromInfo(def, info, &canonical) < 0)
                return -1;
            goto out;
        }
    }

    if (qemudCanonicalizeMachineDirect(def, &canonical) < 0)
        return -1;

out:
    if (canonical) {
        VIR_FREE(def->os.machine);
        def->os.machine = canonical;
    }
    return 0;
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

    if (virSecurityDriverVerify(conn, def) < 0)
        goto cleanup;

    /* See if a VM with matching UUID already exists */
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
    if (vm) {
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(vm->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain '%s' is already defined with uuid %s"),
                             vm->def->name, uuidstr);
            goto cleanup;
        }

        /* UUID & name match */
        virDomainObjUnlock(vm);
        newVM = 0;
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        vm = virDomainFindByName(&driver->domains, def->name);
        if (vm) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain '%s' is already defined with uuid %s"),
                             def->name, uuidstr);
            goto cleanup;
        }
    }

    if (qemudCanonicalizeMachine(driver, def) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(conn,
                                  &driver->domains,
                                  def))) {
        goto cleanup;
    }
    def = NULL;
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
    virDomainDefFree(def);
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
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
                                           virDomainDeviceDefPtr dev,
                                           unsigned int qemuCmdFlags)
{
    virDomainDiskDefPtr origdisk = NULL, newdisk;
    char *devname = NULL;
    int i;
    int ret;

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
        ret = qemuMonitorChangeMedia(vm, devname, newdisk->src);
    } else {
        ret = qemuMonitorEjectMedia(vm, devname);
    }

    if (ret == 0) {
        VIR_FREE(origdisk->src);
        origdisk->src = newdisk->src;
        newdisk->src = NULL;
        origdisk->type = newdisk->type;
    }

    return ret;
}


static int qemudDomainAttachPciDiskDevice(virConnectPtr conn,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev)
{
    int i;
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

    if (qemuMonitorAddPCIDisk(vm,
                              dev->data.disk->src,
                              type,
                              &dev->data.disk->pci_addr.domain,
                              &dev->data.disk->pci_addr.bus,
                              &dev->data.disk->pci_addr.slot) < 0)
        return -1;

    virDomainDiskInsertPreAlloced(vm->def, dev->data.disk);

    return 0;
}

static int qemudDomainAttachUsbMassstorageDevice(virConnectPtr conn,
                                                 virDomainObjPtr vm,
                                                 virDomainDeviceDefPtr dev)
{
    int i;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), dev->data.disk->dst);
            return -1;
        }
    }

    if (!dev->data.disk->src) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("disk source path is missing"));
        return -1;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    if (qemuMonitorAddUSBDisk(vm, dev->data.disk->src) < 0)
        return -1;

    virDomainDiskInsertPreAlloced(vm->def, dev->data.disk);

    return 0;
}

static int qemudDomainAttachNetDevice(virConnectPtr conn,
                                      struct qemud_driver *driver,
                                      virDomainObjPtr vm,
                                      virDomainDeviceDefPtr dev,
                                      unsigned int qemuCmdFlags)
{
    virDomainNetDefPtr net = dev->data.net;
    char *tapfd_name = NULL;
    int i, tapfd = -1;
    char *nicstr = NULL;
    char *netstr = NULL;
    int ret = -1;

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_HOST_NET_ADD)) {
        qemudReportError(conn, dom, NULL, VIR_ERR_NO_SUPPORT, "%s",
                         _("installed qemu version does not support host_net_add"));
        return -1;
    }

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (vm->monitor_chr->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
            qemudReportError(conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                             _("network device type '%s' cannot be attached: "
                               "qemu is not using a unix socket monitor"),
                             virDomainNetTypeToString(net->type));
            return -1;
        }

        if ((tapfd = qemudNetworkIfaceConnect(conn, driver, net, qemuCmdFlags)) < 0)
            return -1;
    }

    if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets+1) < 0)
        goto no_memory;

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NET_NAME) &&
        qemuAssignNetNames(vm->def, net) < 0)
        goto no_memory;

    /* Choose a vlan value greater than all other values since
     * older versions did not store the value in the state file.
     */
    net->vlan = vm->def->nnets;
    for (i = 0; i < vm->def->nnets; i++)
        if (vm->def->nets[i]->vlan >= net->vlan)
            net->vlan = vm->def->nets[i]->vlan;

    if (tapfd != -1) {
        if (virAsprintf(&tapfd_name, "fd-%s", net->hostnet_name) < 0)
            goto no_memory;

        if (qemuMonitorSendFileHandle(vm, tapfd_name, tapfd) < 0)
            goto cleanup;
    }

    if (qemuBuildHostNetStr(conn, net, ' ',
                            net->vlan, tapfd_name, &netstr) < 0)
        goto try_tapfd_close;

    if (qemuMonitorAddHostNetwork(vm, netstr) < 0)
        goto try_tapfd_close;

    if (tapfd != -1)
        close(tapfd);
    tapfd = -1;

    if (qemuBuildNicStr(conn, net, NULL, net->vlan, &nicstr) < 0)
        goto try_remove;

    if (qemuMonitorAddPCINetwork(vm, nicstr,
                                 &net->pci_addr.domain,
                                 &net->pci_addr.bus,
                                 &net->pci_addr.slot) < 0)
        goto try_remove;

    ret = 0;

    vm->def->nets[vm->def->nnets++] = net;

cleanup:
    VIR_FREE(nicstr);
    VIR_FREE(netstr);
    VIR_FREE(tapfd_name);
    if (tapfd != -1)
        close(tapfd);

    return ret;

try_remove:
    if (!net->hostnet_name || net->vlan == 0)
        VIR_WARN0(_("Unable to remove network backend\n"));
    else if (qemuMonitorRemoveHostNetwork(vm, net->vlan, net->hostnet_name) < 0)
        VIR_WARN(_("Failed to remove network backend for vlan %d, net %s"),
                 net->vlan, net->hostnet_name);
    goto cleanup;

try_tapfd_close:
    if (tapfd_name &&
        qemuMonitorCloseFileHandle(vm, tapfd_name) < 0)
        VIR_WARN(_("Failed to close tapfd with '%s'\n"), tapfd_name);

    goto cleanup;

no_memory:
    virReportOOMError(conn);
    goto cleanup;
}

static int qemudDomainAttachHostPciDevice(virConnectPtr conn,
                                          struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;
    pciDevice *pci;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    pci = pciGetDevice(conn,
                       hostdev->source.subsys.u.pci.domain,
                       hostdev->source.subsys.u.pci.bus,
                       hostdev->source.subsys.u.pci.slot,
                       hostdev->source.subsys.u.pci.function);
    if (!dev)
        return -1;

    if ((hostdev->managed && pciDettachDevice(conn, pci) < 0) ||
        pciResetDevice(conn, pci, driver->activePciHostdevs) < 0) {
        pciFreeDevice(conn, pci);
        return -1;
    }

    if (pciDeviceListAdd(conn, driver->activePciHostdevs, pci) < 0) {
        pciFreeDevice(conn, pci);
        return -1;
    }

    if (qemuMonitorAddPCIHostDevice(vm,
                                    hostdev->source.subsys.u.pci.domain,
                                    hostdev->source.subsys.u.pci.bus,
                                    hostdev->source.subsys.u.pci.slot,
                                    hostdev->source.subsys.u.pci.function,
                                    &hostdev->source.subsys.u.pci.guest_addr.domain,
                                    &hostdev->source.subsys.u.pci.guest_addr.bus,
                                    &hostdev->source.subsys.u.pci.guest_addr.slot) < 0)
        goto error;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    return 0;

error:
    pciDeviceListDel(conn, driver->activePciHostdevs, pci);

    return -1;
}

static int qemudDomainAttachHostUsbDevice(virConnectPtr conn,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev)
{
    int ret;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    if (dev->data.hostdev->source.subsys.u.usb.vendor) {
        ret = qemuMonitorAddUSBDeviceMatch(vm,
                                           dev->data.hostdev->source.subsys.u.usb.vendor,
                                           dev->data.hostdev->source.subsys.u.usb.product);
    } else {
        ret = qemuMonitorAddUSBDeviceExact(vm,
                                           dev->data.hostdev->source.subsys.u.usb.bus,
                                           dev->data.hostdev->source.subsys.u.usb.device);
    }

    if (ret != -1)
        vm->def->hostdevs[vm->def->nhostdevs++] = dev->data.hostdev;

    return ret;
}

static int qemudDomainAttachHostDevice(virConnectPtr conn,
                                       struct qemud_driver *driver,
                                       virDomainObjPtr vm,
                                       virDomainDeviceDefPtr dev)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        qemudReportError(conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         _("hostdev mode '%s' not supported"),
                         virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    if (qemuDomainSetDeviceOwnership(conn, driver, dev, 0) < 0)
        return -1;
    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityHostdevLabel(conn, vm, dev->data.hostdev) < 0)
        return -1;

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        return qemudDomainAttachHostPciDevice(conn, driver, vm, dev);
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return qemudDomainAttachHostUsbDevice(conn, vm, dev);
    default:
        qemudReportError(conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         _("hostdev subsys type '%s' not supported"),
                         virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        return -1;
    }
}

static int qemudDomainAttachDevice(virDomainPtr dom,
                                   const char *xml) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDeviceDefPtr dev = NULL;
    unsigned int qemuCmdFlags;
    virCgroupPtr cgroup = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("cannot attach device on inactive domain"));
        goto cleanup;
    }

    dev = virDomainDeviceDefParse(dom->conn, driver->caps, vm->def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto cleanup;

    if (qemudExtractVersionInfo(vm->def->emulator,
                                NULL,
                                &qemuCmdFlags) < 0)
        goto cleanup;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
            if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) !=0 ) {
                qemudReportError(dom->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Unable to find cgroup for %s\n"),
                                 vm->def->name);
                goto cleanup;
            }
            if (dev->data.disk->src != NULL &&
                dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK &&
                virCgroupAllowDevicePath(cgroup,
                                         dev->data.disk->src) < 0) {
                qemudReportError(dom->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unable to allow device %s"),
                                 dev->data.disk->src);
                goto cleanup;
            }
        }

        switch (dev->data.disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            if (driver->securityDriver)
                driver->securityDriver->domainSetSecurityImageLabel(dom->conn, vm, dev->data.disk);

            if (qemuDomainSetDeviceOwnership(dom->conn, driver, dev, 0) < 0)
                goto cleanup;

            ret = qemudDomainChangeEjectableMedia(dom->conn, vm, dev, qemuCmdFlags);
            break;

        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (driver->securityDriver)
                driver->securityDriver->domainSetSecurityImageLabel(dom->conn, vm, dev->data.disk);

            if (qemuDomainSetDeviceOwnership(dom->conn, driver, dev, 0) < 0)
                goto cleanup;

            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                ret = qemudDomainAttachUsbMassstorageDevice(dom->conn, vm, dev);
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
                       dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
                ret = qemudDomainAttachPciDiskDevice(dom->conn, vm, dev);
            } else {
                qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                                 _("disk bus '%s' cannot be hotplugged."),
                                 virDomainDiskBusTypeToString(dev->data.disk->bus));
                /* fallthrough */
            }
            break;

        default:
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                             _("disk device type '%s' cannot be hotplugged"),
                             virDomainDiskDeviceTypeToString(dev->data.disk->device));
            /* Fallthrough */
        }
        if (ret != 0) {
            virCgroupDenyDevicePath(cgroup,
                                    dev->data.disk->src);
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        ret = qemudDomainAttachNetDevice(dom->conn, driver, vm, dev, qemuCmdFlags);
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemudDomainAttachHostDevice(dom->conn, driver, vm, dev);
    } else {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         _("device type '%s' cannot be attached"),
                         virDomainDeviceTypeToString(dev->type));
        goto cleanup;
    }

    if (!ret && virDomainSaveStatus(dom->conn, driver->stateDir, vm) < 0)
        ret = -1;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);

    if (ret < 0 && dev != NULL) {
        if (qemuDomainSetDeviceOwnership(dom->conn, driver, dev, 1) < 0)
            VIR_WARN0("Fail to restore disk device ownership");
        virDomainDeviceDefFree(dev);
    }
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemudDomainDetachPciDiskDevice(virConnectPtr conn,
                                          virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    int i, ret = -1;
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

    if (!virDiskHasValidPciAddr(detach)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("disk %s cannot be detached - no PCI address for device"),
                           detach->dst);
        goto cleanup;
    }

    if (qemuMonitorRemovePCIDevice(vm,
                                   detach->pci_addr.domain,
                                   detach->pci_addr.bus,
                                   detach->pci_addr.slot) < 0)
        goto cleanup;

    if (vm->def->ndisks > 1) {
        memmove(vm->def->disks + i,
                vm->def->disks + i + 1,
                sizeof(*vm->def->disks) *
                (vm->def->ndisks - (i + 1)));
        vm->def->ndisks--;
        if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->disks);
        vm->def->ndisks = 0;
    }
    virDomainDiskDefFree(detach);

    ret = 0;

cleanup:
    return ret;
}

static int
qemudDomainDetachNetDevice(virConnectPtr conn,
                           virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev)
{
    int i, ret = -1;
    virDomainNetDefPtr detach = NULL;

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];

        if (!memcmp(net->mac, dev->data.net->mac,  sizeof(net->mac))) {
            detach = net;
            break;
        }
    }

    if (!detach) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("network device %02x:%02x:%02x:%02x:%02x:%02x not found"),
                         dev->data.net->mac[0], dev->data.net->mac[1],
                         dev->data.net->mac[2], dev->data.net->mac[3],
                         dev->data.net->mac[4], dev->data.net->mac[5]);
        goto cleanup;
    }

    if (!virNetHasValidPciAddr(detach) || detach->vlan < 0 || !detach->hostnet_name) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("network device cannot be detached - device state missing"));
        goto cleanup;
    }

    if (qemuMonitorRemovePCIDevice(vm,
                                   detach->pci_addr.domain,
                                   detach->pci_addr.bus,
                                   detach->pci_addr.slot) < 0)
        goto cleanup;

    if (qemuMonitorRemoveHostNetwork(vm, detach->vlan, detach->hostnet_name) < 0)
        goto cleanup;

    if (vm->def->nnets > 1) {
        memmove(vm->def->nets + i,
                vm->def->nets + i + 1,
                sizeof(*vm->def->nets) *
                (vm->def->nnets - (i + 1)));
        vm->def->nnets--;
        if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->nets);
        vm->def->nnets = 0;
    }
    virDomainNetDefFree(detach);

    ret = 0;

cleanup:
    return ret;
}

static int qemudDomainDetachHostPciDevice(virConnectPtr conn,
                                          struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev)
{
    virDomainHostdevDefPtr detach = NULL;
    int i, ret;
    pciDevice *pci;

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        unsigned domain   = vm->def->hostdevs[i]->source.subsys.u.pci.domain;
        unsigned bus      = vm->def->hostdevs[i]->source.subsys.u.pci.bus;
        unsigned slot     = vm->def->hostdevs[i]->source.subsys.u.pci.slot;
        unsigned function = vm->def->hostdevs[i]->source.subsys.u.pci.function;

        if (dev->data.hostdev->source.subsys.u.pci.domain   == domain &&
            dev->data.hostdev->source.subsys.u.pci.bus      == bus &&
            dev->data.hostdev->source.subsys.u.pci.slot     == slot &&
            dev->data.hostdev->source.subsys.u.pci.function == function) {
            detach = vm->def->hostdevs[i];
            break;
        }
    }

    if (!detach) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("host pci device %.4x:%.2x:%.2x.%.1x not found"),
                         dev->data.hostdev->source.subsys.u.pci.domain,
                         dev->data.hostdev->source.subsys.u.pci.bus,
                         dev->data.hostdev->source.subsys.u.pci.slot,
                         dev->data.hostdev->source.subsys.u.pci.function);
        return -1;
    }

    if (!virHostdevHasValidGuestAddr(detach)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("hostdev cannot be detached - device state missing"));
        return -1;
    }

    if (qemuMonitorRemovePCIDevice(vm,
                                   detach->source.subsys.u.pci.guest_addr.domain,
                                   detach->source.subsys.u.pci.guest_addr.bus,
                                   detach->source.subsys.u.pci.guest_addr.slot) < 0)
        return -1;

    ret = 0;

    pci = pciGetDevice(conn,
                       detach->source.subsys.u.pci.domain,
                       detach->source.subsys.u.pci.bus,
                       detach->source.subsys.u.pci.slot,
                       detach->source.subsys.u.pci.function);
    if (!pci)
        ret = -1;
    else {
        pciDeviceListDel(conn, driver->activePciHostdevs, pci);
        if (pciResetDevice(conn, pci, driver->activePciHostdevs) < 0)
            ret = -1;
        if (detach->managed && pciReAttachDevice(conn, pci) < 0)
            ret = -1;
        pciFreeDevice(conn, pci);
    }

    if (vm->def->nhostdevs > 1) {
        memmove(vm->def->hostdevs + i,
                vm->def->hostdevs + i + 1,
                sizeof(*vm->def->hostdevs) *
                (vm->def->nhostdevs - (i + 1)));
        vm->def->nhostdevs--;
        if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->hostdevs);
        vm->def->nhostdevs = 0;
    }
    virDomainHostdevDefFree(detach);

    return ret;
}

static int qemudDomainDetachHostDevice(virConnectPtr conn,
                                       struct qemud_driver *driver,
                                       virDomainObjPtr vm,
                                       virDomainDeviceDefPtr dev)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;
    int ret;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        qemudReportError(conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         _("hostdev mode '%s' not supported"),
                         virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        ret = qemudDomainDetachHostPciDevice(conn, driver, vm, dev);
        break;
    default:
        qemudReportError(conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         _("hostdev subsys type '%s' not supported"),
                         virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        return -1;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityHostdevLabel(conn, vm, dev->data.hostdev) < 0)
        VIR_WARN0("Failed to restore device labelling");

    if (qemuDomainSetDeviceOwnership(conn, driver, dev, 1) < 0)
        VIR_WARN0("Failed to restore device ownership");

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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("cannot detach device on inactive domain"));
        goto cleanup;
    }

    dev = virDomainDeviceDefParse(dom->conn, driver->caps, vm->def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto cleanup;


    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
         dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)) {
        ret = qemudDomainDetachPciDiskDevice(dom->conn, vm, dev);
        if (driver->securityDriver)
            driver->securityDriver->domainRestoreSecurityImageLabel(dom->conn, vm, dev->data.disk);
        if (qemuDomainSetDeviceOwnership(dom->conn, driver, dev, 1) < 0)
            VIR_WARN0("Fail to restore disk device ownership");
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        ret = qemudDomainDetachNetDevice(dom->conn, vm, dev);
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemudDomainDetachHostDevice(dom->conn, driver, vm, dev);
    } else
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("only SCSI or virtio disk device can be detached dynamically"));

    if (!ret && virDomainSaveStatus(dom->conn, driver->stateDir, vm) < 0)
        ret = -1;

cleanup:
    virDomainDeviceDefFree(dev);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
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

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
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
    qemuDriverUnlock(driver);
    return ret;
}


static char *qemuGetSchedulerType(virDomainPtr dom,
                                  int *nparams)
{
    struct qemud_driver *driver = dom->conn->privateData;
    char *ret = NULL;

    qemuDriverLock(driver);
    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         __FUNCTION__);
        goto cleanup;
    }

    if (nparams)
        *nparams = 1;

    ret = strdup("posix");
    if (!ret)
        virReportOOMError(dom->conn);

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuSetSchedulerParameters(virDomainPtr dom,
                                      virSchedParameterPtr params,
                                      int nparams)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         __FUNCTION__);
        goto cleanup;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    for (i = 0; i < nparams; i++) {
        virSchedParameterPtr param = &params[i];

        if (STREQ(param->field, "cpu_shares")) {
            int rc;
            if (param->type != VIR_DOMAIN_SCHED_FIELD_ULLONG) {
                qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                                 _("invalid type for cpu_shares tunable, expected a 'ullong'"));
                goto cleanup;
            }

            rc = virCgroupSetCpuShares(group, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(dom->conn, -rc, "%s",
                                     _("unable to set cpu shares tunable"));
                goto cleanup;
            }
        } else {
            qemudReportError(dom->conn, domain, NULL, VIR_ERR_INVALID_ARG,
                             _("Invalid parameter `%s'"), param->field);
            goto cleanup;
        }
    }
    ret = 0;

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuGetSchedulerParameters(virDomainPtr dom,
                                      virSchedParameterPtr params,
                                      int *nparams)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long long val;
    int ret = -1;
    int rc;

    qemuDriverLock(driver);
    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         __FUNCTION__);
        goto cleanup;
    }

    if ((*nparams) != 1) {
        qemudReportError(dom->conn, domain, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("Invalid parameter count"));
        goto cleanup;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemudReportError(dom->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    rc = virCgroupGetCpuShares(group, &val);
    if (rc != 0) {
        virReportSystemError(dom->conn, -rc, "%s",
                             _("unable to get cpu shares tunable"));
        goto cleanup;
    }
    params[0].value.ul = val;
    params[0].type = VIR_DOMAIN_SCHED_FIELD_ULLONG;
    if (virStrcpyStatic(params[0].field, "cpu_shares") == NULL) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Field cpu_shares too long for destination"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
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
    const char *qemu_dev_name = NULL;
    int i, ret = -1;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    if (!virDomainIsActive (vm)) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
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

    if (qemuMonitorGetBlockStatsInfo(vm, qemu_dev_name,
                                     &stats->rd_req,
                                     &stats->rd_bytes,
                                     &stats->wr_req,
                                     &stats->wr_bytes,
                                     &stats->errs) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(qemu_dev_name);
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
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
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
    char *tmp = NULL;
    int fd = -1, ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (flags != VIR_MEMORY_VIRTUAL && flags != VIR_MEMORY_PHYSICAL) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                     "%s", _("flags parameter must be VIR_MEMORY_VIRTUAL or VIR_MEMORY_PHYSICAL"));
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto cleanup;
    }

    if (virAsprintf(&tmp, driver->cacheDir,  "/qemu.mem.XXXXXX") < 0) {
        virReportOOMError(dom->conn);
        goto cleanup;
    }

    /* Create a temporary filename. */
    if ((fd = mkstemp (tmp)) == -1) {
        virReportSystemError (dom->conn, errno,
                              _("mkstemp(\"%s\") failed"), tmp);
        goto cleanup;
    }

    if (flags == VIR_MEMORY_VIRTUAL) {
        if (qemuMonitorSaveVirtualMemory(vm, offset, size, tmp) < 0)
            goto cleanup;
    } else {
        if (qemuMonitorSavePhysicalMemory(vm, offset, size, tmp) < 0)
            goto cleanup;
    }

    /* Read the memory file into buffer. */
    if (saferead (fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError (dom->conn, errno,
                              _("failed to read temporary file "
                                "created with template %s"), tmp);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(tmp);
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

/* Tunnelled migration stream support */
struct qemuStreamMigFile {
    int fd;

    int watch;
    unsigned int cbRemoved;
    unsigned int dispatching;
    virStreamEventCallback cb;
    void *opaque;
    virFreeCallback ff;
};

static int qemuStreamMigRemoveCallback(virStreamPtr stream)
{
    struct qemud_driver *driver = stream->conn->privateData;
    struct qemuStreamMigFile *qemust = stream->privateData;
    int ret = -1;

    if (!qemust) {
        qemudReportError(stream->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("stream is not open"));
        return -1;
    }

    qemuDriverLock(driver);
    if (qemust->watch == 0) {
        qemudReportError(stream->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("stream does not have a callback registered"));
        goto cleanup;
    }

    virEventRemoveHandle(qemust->watch);
    if (qemust->dispatching)
        qemust->cbRemoved = 1;
    else if (qemust->ff)
        (qemust->ff)(qemust->opaque);

    qemust->watch = 0;
    qemust->ff = NULL;
    qemust->cb = NULL;
    qemust->opaque = NULL;

    ret = 0;

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuStreamMigUpdateCallback(virStreamPtr stream, int events)
{
    struct qemud_driver *driver = stream->conn->privateData;
    struct qemuStreamMigFile *qemust = stream->privateData;
    int ret = -1;

    if (!qemust) {
        qemudReportError(stream->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("stream is not open"));
        return -1;
    }

    qemuDriverLock(driver);
    if (qemust->watch == 0) {
        qemudReportError(stream->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("stream does not have a callback registered"));
        goto cleanup;
    }

    virEventUpdateHandle(qemust->watch, events);

    ret = 0;

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

static void qemuStreamMigEvent(int watch ATTRIBUTE_UNUSED,
                               int fd ATTRIBUTE_UNUSED,
                               int events,
                               void *opaque)
{
    virStreamPtr stream = opaque;
    struct qemud_driver *driver = stream->conn->privateData;
    struct qemuStreamMigFile *qemust = stream->privateData;
    virStreamEventCallback cb;
    void *cbopaque;
    virFreeCallback ff;

    qemuDriverLock(driver);
    if (!qemust || !qemust->cb) {
        qemuDriverUnlock(driver);
        return;
    }

    cb = qemust->cb;
    cbopaque = qemust->opaque;
    ff = qemust->ff;
    qemust->dispatching = 1;
    qemuDriverUnlock(driver);

    cb(stream, events, cbopaque);

    qemuDriverLock(driver);
    qemust->dispatching = 0;
    if (qemust->cbRemoved && ff)
        (ff)(cbopaque);
    qemuDriverUnlock(driver);
}

static int
qemuStreamMigAddCallback(virStreamPtr st,
                         int events,
                         virStreamEventCallback cb,
                         void *opaque,
                         virFreeCallback ff)
{
    struct qemud_driver *driver = st->conn->privateData;
    struct qemuStreamMigFile *qemust = st->privateData;
    int ret = -1;

    if (!qemust) {
        qemudReportError(st->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("stream is not open"));
        return -1;
    }

    qemuDriverLock(driver);
    if (qemust->watch != 0) {
        qemudReportError(st->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("stream already has a callback registered"));
        goto cleanup;
    }

    if ((qemust->watch = virEventAddHandle(qemust->fd,
                                           events,
                                           qemuStreamMigEvent,
                                           st,
                                           NULL)) < 0) {
        qemudReportError(st->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot register file watch on stream"));
        goto cleanup;
    }

    qemust->cbRemoved = 0;
    qemust->cb = cb;
    qemust->opaque = opaque;
    qemust->ff = ff;
    virStreamRef(st);

    ret = 0;

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

static void qemuStreamMigFree(struct qemuStreamMigFile *qemust)
{
    if (qemust->fd != -1)
        close(qemust->fd);
    VIR_FREE(qemust);
}

static struct qemuStreamMigFile *qemuStreamMigOpen(virStreamPtr st,
                                                   const char *unixfile)
{
    struct qemuStreamMigFile *qemust = NULL;
    struct sockaddr_un sa_qemu;
    int i = 0;
    int timeout = 3;
    int ret;

    if (VIR_ALLOC(qemust) < 0)
        return NULL;

    qemust->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (qemust->fd < 0)
        goto cleanup;

    memset(&sa_qemu, 0, sizeof(sa_qemu));
    sa_qemu.sun_family = AF_UNIX;
    if (virStrcpy(sa_qemu.sun_path, unixfile, sizeof(sa_qemu.sun_path)) == NULL)
        goto cleanup;

    do {
        ret = connect(qemust->fd, (struct sockaddr *)&sa_qemu, sizeof(sa_qemu));
        if (ret == 0)
            break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        goto cleanup;
    } while ((++i <= timeout*5) && (usleep(.2 * 1000000) <= 0));

    if ((st->flags & VIR_STREAM_NONBLOCK) && virSetNonBlock(qemust->fd) < 0)
        goto cleanup;

    return qemust;

cleanup:
    qemuStreamMigFree(qemust);
    return NULL;
}

static int
qemuStreamMigClose(virStreamPtr st)
{
    struct qemud_driver *driver = st->conn->privateData;
    struct qemuStreamMigFile *qemust = st->privateData;

    if (!qemust)
        return 0;

    qemuDriverLock(driver);

    qemuStreamMigFree(qemust);

    st->privateData = NULL;

    qemuDriverUnlock(driver);

    return 0;
}

static int qemuStreamMigWrite(virStreamPtr st, const char *bytes, size_t nbytes)
{
    struct qemud_driver *driver = st->conn->privateData;
    struct qemuStreamMigFile *qemust = st->privateData;
    int ret;

    if (!qemust) {
        qemudReportError(st->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("stream is not open"));
        return -1;
    }

    qemuDriverLock(driver);

retry:
    ret = write(qemust->fd, bytes, nbytes);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ret = -2;
        } else if (errno == EINTR) {
            goto retry;
        } else {
            ret = -1;
            virReportSystemError(st->conn, errno, "%s",
                                 _("cannot write to stream"));
        }
    }

    qemuDriverUnlock(driver);
    return ret;
}

static virStreamDriver qemuStreamMigDrv = {
    .streamSend = qemuStreamMigWrite,
    .streamFinish = qemuStreamMigClose,
    .streamAbort = qemuStreamMigClose,
    .streamAddCallback = qemuStreamMigAddCallback,
    .streamUpdateCallback = qemuStreamMigUpdateCallback,
    .streamRemoveCallback = qemuStreamMigRemoveCallback
};

/* Prepare is the first step, and it runs on the destination host.
 *
 * This version starts an empty VM listening on a localhost TCP port, and
 * sets up the corresponding virStream to handle the incoming data.
 */
static int
qemudDomainMigratePrepareTunnel(virConnectPtr dconn,
                                virStreamPtr st,
                                unsigned long flags,
                                const char *dname,
                                unsigned long resource ATTRIBUTE_UNUSED,
                                const char *dom_xml)
{
    struct qemud_driver *driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    char *migrateFrom;
    virDomainEventPtr event = NULL;
    int ret = -1;
    int internalret;
    char *unixfile = NULL;
    unsigned int qemuCmdFlags;
    struct qemuStreamMigFile *qemust = NULL;

    qemuDriverLock(driver);
    if (!dom_xml) {
        qemudReportError(dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("no domain XML passed"));
        goto cleanup;
    }
    if (!(flags & VIR_MIGRATE_TUNNELLED)) {
        qemudReportError(dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("PrepareTunnel called but no TUNNELLED flag set"));
        goto cleanup;
    }
    if (st == NULL) {
        qemudReportError(dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("tunnelled migration requested but NULL stream passed"));
        goto cleanup;
    }

    /* Parse the domain XML. */
    if (!(def = virDomainDefParseString(dconn, driver->caps, dom_xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        qemudReportError(dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to parse XML"));
        goto cleanup;
    }

    /* Target domain name, maybe renamed. */
    dname = dname ? dname : def->name;

    /* Ensure the name and UUID don't already exist in an active VM */
    vm = virDomainFindByUUID(&driver->domains, def->uuid);

    if (!vm) vm = virDomainFindByName(&driver->domains, dname);
    if (vm) {
        if (virDomainIsActive(vm)) {
            qemudReportError(dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("domain with the same name or UUID already exists as '%s'"),
                             vm->def->name);
            goto cleanup;
        }
        virDomainObjUnlock(vm);
    }

    if (!(vm = virDomainAssignDef(dconn,
                                  &driver->domains,
                                  def))) {
        qemudReportError(dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to assign new VM"));
        goto cleanup;
    }
    def = NULL;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (virAsprintf(&unixfile, "%s/qemu.tunnelmigrate.dest.%s",
                    driver->stateDir, vm->def->name) < 0) {
        virReportOOMError (dconn);
        goto cleanup;
    }
    unlink(unixfile);

    /* check that this qemu version supports the interactive exec */
    if (qemudExtractVersionInfo(vm->def->emulator, NULL, &qemuCmdFlags) < 0) {
        qemudReportError(dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot determine QEMU argv syntax %s"),
                         vm->def->emulator);
        goto cleanup;
    }
    if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX)
        internalret = virAsprintf(&migrateFrom, "unix:%s", unixfile);
    else if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC)
        internalret = virAsprintf(&migrateFrom, "exec:nc -U -l %s", unixfile);
    else {
        qemudReportError(dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("Destination qemu is too old to support tunnelled migration"));
        goto cleanup;
    }
    if (internalret < 0) {
        virReportOOMError(dconn);
        goto cleanup;
    }
    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming unix:/path/to/file or exec:nc -U /path/to/file
     */
    internalret = qemudStartVMDaemon(dconn, driver, vm, migrateFrom, -1);
    VIR_FREE(migrateFrom);
    if (internalret < 0) {
        /* Note that we don't set an error here because qemudStartVMDaemon
         * should have already done that.
         */
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        goto cleanup;
    }

    qemust = qemuStreamMigOpen(st, unixfile);
    if (qemust == NULL) {
        qemudShutdownVMDaemon(NULL, driver, vm);
        virReportSystemError(dconn, errno,
                             _("cannot open unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto cleanup;
    }

    st->driver = &qemuStreamMigDrv;
    st->privateData = qemust;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

cleanup:
    virDomainDefFree(def);
    unlink(unixfile);
    VIR_FREE(unixfile);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

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
                            unsigned long flags,
                            const char *dname,
                            unsigned long resource ATTRIBUTE_UNUSED,
                            const char *dom_xml)
{
    static int port = 0;
    struct qemud_driver *driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int this_port;
    char *hostname;
    char migrateFrom [64];
    const char *p;
    virDomainEventPtr event = NULL;
    int ret = -1;
    int internalret;

    *uri_out = NULL;

    qemuDriverLock(driver);
    if (flags & VIR_MIGRATE_TUNNELLED) {
        /* this is a logical error; we never should have gotten here with
         * VIR_MIGRATE_TUNNELLED set
         */
        qemudReportError(dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Tunnelled migration requested but invalid RPC method called"));
        goto cleanup;
    }

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
        if ((hostname = virGetHostname()) == NULL) {
            virReportSystemError (dconn, errno,
                                  "%s", _("failed to determine host name"));
            goto cleanup;
        }

        /* XXX this really should have been a properly well-formed
         * URI, but we can't add in tcp:// now without breaking
         * compatability with old targets. We at least make the
         * new targets accept both syntaxes though.
         */
        /* Caller frees */
        internalret = virAsprintf(uri_out, "tcp:%s:%d", hostname, this_port);
        VIR_FREE(hostname);
        if (internalret < 0) {
            virReportOOMError (dconn);
            goto cleanup;
        }
    } else {
        /* Check the URI starts with "tcp:".  We will escape the
         * URI when passing it to the qemu monitor, so bad
         * characters in hostname part don't matter.
         */
        if (!STRPREFIX (uri_in, "tcp:")) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_INVALID_ARG,
                  "%s", _("only tcp URIs are supported for KVM/QEMU migrations"));
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
        virDomainObjUnlock(vm);
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
        /* Note that we don't set an error here because qemudStartVMDaemon
         * should have already done that.
         */
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


/* Perform migration using QEMU's native TCP migrate support,
 * not encrypted obviously
 */
static int doNativeMigrate(virDomainPtr dom,
                           virDomainObjPtr vm,
                           const char *uri,
                           unsigned long flags ATTRIBUTE_UNUSED,
                           const char *dname ATTRIBUTE_UNUSED,
                           unsigned long resource)
{
    int ret = -1;
    xmlURIPtr uribits = NULL;
    int status;
    unsigned long long transferred, remaining, total;

    /* Issue the migrate command. */
    if (STRPREFIX(uri, "tcp:") && !STRPREFIX(uri, "tcp://")) {
        /* HACK: source host generates bogus URIs, so fix them up */
        char *tmpuri;
        if (virAsprintf(&tmpuri, "tcp://%s", uri + strlen("tcp:")) < 0) {
            virReportOOMError(dom->conn);
            goto cleanup;
        }
        uribits = xmlParseURI(tmpuri);
        VIR_FREE(tmpuri);
    } else {
        uribits = xmlParseURI(uri);
    }
    if (!uribits) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse URI %s"), uri);
        goto cleanup;
    }

    if (resource > 0 &&
        qemuMonitorSetMigrationSpeed(vm, resource) < 0)
        goto cleanup;

    if (qemuMonitorMigrateToHost(vm, 0, uribits->server, uribits->port) < 0)
        goto cleanup;

    /* it is also possible that the migrate didn't fail initially, but
     * rather failed later on.  Check the output of "info migrate"
     */
    if (qemuMonitorGetMigrationStatus(vm, &status,
                                      &transferred,
                                      &remaining,
                                      &total) < 0) {
        goto cleanup;
    }

    if (status != QEMU_MONITOR_MIGRATION_STATUS_COMPLETED) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("migrate did not successfully complete"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    xmlFreeURI(uribits);
    return ret;
}


static int doTunnelSendAll(virDomainPtr dom,
                           virStreamPtr st,
                           int sock)
{
    char buffer[65536];
    int nbytes = sizeof(buffer);

    /* XXX should honour the 'resource' parameter here */
    for (;;) {
        nbytes = saferead(sock, buffer, nbytes);
        if (nbytes < 0) {
            virStreamAbort(st);
            virReportSystemError(dom->conn, errno, "%s",
                                 _("tunnelled migration failed to read from qemu"));
            return -1;
        }
        else if (nbytes == 0)
            /* EOF; get out of here */
            break;

        if (virStreamSend(st, buffer, nbytes) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                             _("Failed to write migration data to remote libvirtd"));
            return -1;
        }
    }

    if (virStreamFinish(st) < 0)
        /* virStreamFinish set the error for us */
        return -1;

    return 0;
}

static int doTunnelMigrate(virDomainPtr dom,
                           virConnectPtr dconn,
                           virDomainObjPtr vm,
                           const char *dom_xml,
                           const char *uri,
                           unsigned long flags,
                           const char *dname,
                           unsigned long resource)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int client_sock = -1;
    int qemu_sock = -1;
    struct sockaddr_un sa_qemu, sa_client;
    socklen_t addrlen;
    virDomainPtr ddomain = NULL;
    int retval = -1;
    virStreamPtr st = NULL;
    char *unixfile = NULL;
    int internalret;
    unsigned int qemuCmdFlags;
    int status;
    unsigned long long transferred, remaining, total;

    /*
     * The order of operations is important here to avoid touching
     * the source VM until we are very sure we can successfully
     * start the migration operation.
     *
     *   1. setup local support infrastructure (eg sockets)
     *   2. setup destination fully
     *   3. start migration on source
     */


    /* Stage 1. setup local support infrastructure */

    if (virAsprintf(&unixfile, "%s/qemu.tunnelmigrate.src.%s",
                    driver->stateDir, vm->def->name) < 0) {
        virReportOOMError(dom->conn);
        goto cleanup;
    }

    qemu_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (qemu_sock < 0) {
        virReportSystemError(dom->conn, errno, "%s",
                             _("cannot open tunnelled migration socket"));
        goto cleanup;
    }
    memset(&sa_qemu, 0, sizeof(sa_qemu));
    sa_qemu.sun_family = AF_UNIX;
    if (virStrcpy(sa_qemu.sun_path, unixfile,
                  sizeof(sa_qemu.sun_path)) == NULL) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unix socket '%s' too big for destination"),
                         unixfile);
        goto cleanup;
    }
    unlink(unixfile);
    if (bind(qemu_sock, (struct sockaddr *)&sa_qemu, sizeof(sa_qemu)) < 0) {
        virReportSystemError(dom->conn, errno,
                             _("Cannot bind to unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto cleanup;
    }
    if (listen(qemu_sock, 1) < 0) {
        virReportSystemError(dom->conn, errno,
                             _("Cannot listen on unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto cleanup;
    }

    /* check that this qemu version supports the unix migration */
    if (qemudExtractVersionInfo(vm->def->emulator, NULL, &qemuCmdFlags) < 0) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot extract Qemu version from '%s'"),
                         vm->def->emulator);
        goto cleanup;
    }

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX) &&
        !(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC)) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("Source qemu is too old to support tunnelled migration"));
        goto cleanup;
    }


    /* Stage 2. setup destination fully
     *
     * Once stage 2 has completed successfully, we *must* call finish
     * to cleanup the target whether we succeed or fail
     */
    st = virStreamNew(dconn, 0);
    if (st == NULL)
        /* virStreamNew only fails on OOM, and it reports the error itself */
        goto cleanup;

    internalret = dconn->driver->domainMigratePrepareTunnel(dconn, st,
                                                            flags, dname,
                                                            resource, dom_xml);

    if (internalret < 0)
        /* domainMigratePrepareTunnel sets the error for us */
        goto cleanup;

    /*   3. start migration on source */
    if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX)
        internalret = qemuMonitorMigrateToUnix(vm, 1, unixfile);
    else if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC) {
        const char *args[] = { "nc", "-U", unixfile, NULL };
        internalret = qemuMonitorMigrateToCommand(vm, 1, args, "/dev/null");
    } else {
        internalret = -1;
    }
    if (internalret < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("tunnelled migration monitor command failed"));
        goto finish;
    }

    /* From this point onwards we *must* call cancel to abort the
     * migration on source if anything goes wrong */

    /* it is also possible that the migrate didn't fail initially, but
     * rather failed later on.  Check the output of "info migrate"
     */
    if (qemuMonitorGetMigrationStatus(vm, &status,
                                      &transferred,
                                      &remaining,
                                      &total) < 0) {
        goto cancel;
    }

    if (status == QEMU_MONITOR_MIGRATION_STATUS_ERROR) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s",_("migrate failed"));
        goto cancel;
    }

    addrlen = sizeof(sa_client);
    while ((client_sock = accept(qemu_sock, (struct sockaddr *)&sa_client, &addrlen)) < 0) {
        if (errno == EAGAIN || errno == EINTR)
            continue;
        virReportSystemError(dom->conn, errno, "%s",
                             _("tunnelled migration failed to accept from qemu"));
        goto cancel;
    }

    retval = doTunnelSendAll(dom, st, client_sock);

cancel:
    if (retval != 0)
        qemuMonitorMigrateCancel(vm);

finish:
    dname = dname ? dname : dom->name;
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, NULL, 0, uri, flags, retval);

cleanup:
    if (client_sock != -1)
        close(client_sock);
    if (qemu_sock != -1)
        close(qemu_sock);

    if (ddomain)
        virUnrefDomain(ddomain);

    if (unixfile) {
        unlink(unixfile);
        VIR_FREE(unixfile);
    }

    if (st)
        /* don't call virStreamFree(), because that resets any pending errors */
        virUnrefStream(st);
    return retval;
}


/* This is essentially a simplified re-impl of
 * virDomainMigrateVersion2 from libvirt.c, but running in source
 * libvirtd context, instead of client app context */
static int doNonTunnelMigrate(virDomainPtr dom,
                              virConnectPtr dconn,
                              virDomainObjPtr vm,
                              const char *dom_xml,
                              const char *uri ATTRIBUTE_UNUSED,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource)
{
    virDomainPtr ddomain = NULL;
    int retval = -1;
    char *uri_out = NULL;

    /* NB we don't pass 'uri' into this, since that's the libvirtd
     * URI in this context - so we let dest pick it */
    if (dconn->driver->domainMigratePrepare2(dconn,
                                             NULL, /* cookie */
                                             0, /* cookielen */
                                             NULL, /* uri */
                                             &uri_out,
                                             flags, dname,
                                             resource, dom_xml) < 0)
        /* domainMigratePrepare2 sets the error for us */
        goto cleanup;

    if (uri_out == NULL) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("domainMigratePrepare2 did not set uri"));
    }

    if (doNativeMigrate(dom, vm, uri_out, flags, dname, resource) < 0)
        goto finish;

    retval = 0;

finish:
    dname = dname ? dname : dom->name;
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, NULL, 0, uri_out, flags, retval);

    if (ddomain)
        virUnrefDomain(ddomain);

cleanup:
    return retval;
}


static int doPeer2PeerMigrate(virDomainPtr dom,
                              virDomainObjPtr vm,
                              const char *uri,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource)
{
    int ret = -1;
    virConnectPtr dconn = NULL;
    char *dom_xml;

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    dconn = virConnectOpen(uri);
    if (dconn == NULL) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         _("Failed to connect to remote libvirt URI %s"), uri);
        return -1;
    }
    if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                  VIR_DRV_FEATURE_MIGRATION_P2P)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "%s",
                         _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    dom_xml = virDomainDefFormat(dom->conn, vm->def, VIR_DOMAIN_XML_SECURE);
    if (!dom_xml) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to get domain xml"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = doTunnelMigrate(dom, dconn, vm, dom_xml, uri, flags, dname, resource);
    else
        ret = doNonTunnelMigrate(dom, dconn, vm, dom_xml, uri, flags, dname, resource);

cleanup:
    VIR_FREE(dom_xml);
    /* don't call virConnectClose(), because that resets any pending errors */
    virUnrefConnect(dconn);

    return ret;
}


/* Perform is the second step, and it runs on the source host. */
static int
qemudDomainMigratePerform (virDomainPtr dom,
                           const char *cookie ATTRIBUTE_UNUSED,
                           int cookielen ATTRIBUTE_UNUSED,
                           const char *uri,
                           unsigned long flags,
                           const char *dname,
                           unsigned long resource)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    int paused = 0;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_INVALID,
                          "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!(flags & VIR_MIGRATE_LIVE)) {
        /* Pause domain for non-live migration */
        if (qemuMonitorStopCPUs(vm) < 0)
            goto cleanup;
        paused = 1;

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
        if (event)
            qemuDomainEventQueue(driver, event);
        event = NULL;
    }

    if ((flags & VIR_MIGRATE_TUNNELLED)) {
        if (doPeer2PeerMigrate(dom, vm, uri, flags, dname, resource) < 0)
            /* doTunnelMigrate already set the error, so just get out */
            goto cleanup;
    } else {
        if (doNativeMigrate(dom, vm, uri, flags, dname, resource) < 0)
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
    if (paused) {
        /* we got here through some sort of failure; start the domain again */
        if (qemuMonitorStartCPUs(dom->conn, vm) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best
             */
            VIR_ERROR(_("Failed to resume guest %s after failure\n"),
                      vm->def->name);
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

    qemuDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dname);
    if (!vm) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_NO_DOMAIN,
                          _("no domain with matching name '%s'"), dname);
        goto cleanup;
    }

    /* Did the migration go as planned?  If yes, return the domain
     * object, but if no, clean up the empty qemu process.
     */
    if (retcode == 0) {
        dom = virGetDomain (dconn, vm->def->name, vm->def->uuid);

        /* run 'cont' on the destination, which allows migration on qemu
         * >= 0.10.6 to work properly.  This isn't strictly necessary on
         * older qemu's, but it also doesn't hurt anything there
         */
        if (qemuMonitorStartCPUs(dconn, vm) < 0) {
            if (virGetLastError() == NULL)
                qemudReportError(dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("resume operation failed"));
            goto cleanup;
        }

        vm->state = VIR_DOMAIN_RUNNING;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        virDomainSaveStatus(dconn, driver->stateDir, vm);
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

    def = virNodeDeviceDefParseString(dev->conn, xml, EXISTING_DEVICE);
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
    struct qemud_driver *driver = dev->conn->privateData;
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (qemudNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(dev->conn, domain, bus, slot, function);
    if (!pci)
        return -1;

    qemuDriverLock(driver);

    if (pciResetDevice(dev->conn, pci, driver->activePciHostdevs) < 0)
        goto out;

    ret = 0;
out:
    qemuDriverUnlock(driver);
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
    qemudGetHostname, /* getHostname */
    qemudGetMaxVCPUs, /* getMaxVcpus */
    nodeGetInfo, /* nodeGetInfo */
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
    qemudDomainCoreDump, /* domainCoreDump */
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
    qemuDomainXMLFromNative, /* domainXmlFromNative */
    qemuDomainXMLToNative, /* domainXMLToNative */
    qemudListDefinedDomains, /* listDefinedDomains */
    qemudNumDefinedDomains, /* numOfDefinedDomains */
    qemudDomainStart, /* domainCreate */
    qemudDomainDefine, /* domainDefineXML */
    qemudDomainUndefine, /* domainUndefine */
    qemudDomainAttachDevice, /* domainAttachDevice */
    qemudDomainDetachDevice, /* domainDetachDevice */
    qemudDomainGetAutostart, /* domainGetAutostart */
    qemudDomainSetAutostart, /* domainSetAutostart */
    qemuGetSchedulerType, /* domainGetSchedulerType */
    qemuGetSchedulerParameters, /* domainGetSchedulerParameters */
    qemuSetSchedulerParameters, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare (v1) */
    qemudDomainMigratePerform, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    qemudDomainBlockStats, /* domainBlockStats */
    qemudDomainInterfaceStats, /* domainInterfaceStats */
    qemudDomainBlockPeek, /* domainBlockPeek */
    qemudDomainMemoryPeek, /* domainMemoryPeek */
    nodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    nodeGetFreeMemory,  /* getFreeMemory */
    qemudDomainEventRegister, /* domainEventRegister */
    qemudDomainEventDeregister, /* domainEventDeregister */
    qemudDomainMigratePrepare2, /* domainMigratePrepare2 */
    qemudDomainMigrateFinish2, /* domainMigrateFinish2 */
    qemudNodeDeviceDettach, /* nodeDeviceDettach */
    qemudNodeDeviceReAttach, /* nodeDeviceReAttach */
    qemudNodeDeviceReset, /* nodeDeviceReset */
    qemudDomainMigratePrepareTunnel, /* domainMigratePrepareTunnel */
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
