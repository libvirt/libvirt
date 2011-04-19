/*
 * qemu_process.h: QEMU process management
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 */

#include <config.h>

#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "qemu_process.h"
#include "qemu_domain.h"
#include "qemu_cgroup.h"
#include "qemu_capabilities.h"
#include "qemu_monitor.h"
#include "qemu_command.h"
#include "qemu_audit.h"
#include "qemu_hostdev.h"
#include "qemu_hotplug.h"
#include "qemu_bridge_filter.h"

#include "datatypes.h"
#include "logging.h"
#include "virterror_internal.h"
#include "memory.h"
#include "hooks.h"
#include "files.h"
#include "util.h"
#include "c-ctype.h"
#include "nodeinfo.h"
#include "processinfo.h"
#include "domain_nwfilter.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define START_POSTFIX ": starting up\n"
#define SHUTDOWN_POSTFIX ": shutting down\n"

/**
 * qemudRemoveDomainStatus
 *
 * remove all state files of a domain from statedir
 *
 * Returns 0 on success
 */
static int
qemuProcessRemoveDomainStatus(struct qemud_driver *driver,
                              virDomainObjPtr vm)
{
    char ebuf[1024];
    char *file = NULL;

    if (virAsprintf(&file, "%s/%s.xml", driver->stateDir, vm->def->name) < 0) {
        virReportOOMError();
        return(-1);
    }

    if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
        VIR_WARN("Failed to remove domain XML for %s: %s",
                 vm->def->name, virStrerror(errno, ebuf, sizeof(ebuf)));
    VIR_FREE(file);

    if (virFileDeletePid(driver->stateDir, vm->def->name) != 0)
        VIR_WARN("Failed to remove PID file for %s: %s",
                 vm->def->name, virStrerror(errno, ebuf, sizeof(ebuf)));


    return 0;
}


/* XXX figure out how to remove this */
extern struct qemud_driver *qemu_driver;

/*
 * This is a callback registered with a qemuMonitorPtr  instance,
 * and to be invoked when the monitor console hits an end of file
 * condition, or error, thus indicating VM shutdown should be
 * performed
 */
static void
qemuProcessHandleMonitorEOF(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                            virDomainObjPtr vm,
                            int hasError)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;

    VIR_DEBUG("Received EOF on %p '%s'", vm, vm->def->name);

    qemuDriverLock(driver);
    virDomainObjLock(vm);

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Domain %p is not active, ignoring EOF", vm);
        virDomainObjUnlock(vm);
        qemuDriverUnlock(driver);
        return;
    }

    priv = vm->privateData;
    if (!hasError && priv->monJSON && !priv->gotShutdown) {
        VIR_DEBUG("Monitor connection to '%s' closed without SHUTDOWN event; "
                  "assuming the domain crashed", vm->def->name);
        hasError = 1;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     hasError ?
                                     VIR_DOMAIN_EVENT_STOPPED_FAILED :
                                     VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);

    qemuProcessStop(driver, vm, 0);
    qemuAuditDomainStop(vm, hasError ? "failed" : "shutdown");

    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains, vm);
    else
        virDomainObjUnlock(vm);

    if (event) {
        qemuDomainEventQueue(driver, event);
    }
    qemuDriverUnlock(driver);
}


static virDomainDiskDefPtr
qemuProcessFindDomainDiskByPath(virDomainObjPtr vm,
                                const char *path)
{
    int i;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk;

        disk = vm->def->disks[i];
        if (disk->src != NULL && STREQ(disk->src, path))
            return disk;
    }

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("no disk found with path %s"),
                    path);
    return NULL;
}

static virDomainDiskDefPtr
qemuProcessFindDomainDiskByAlias(virDomainObjPtr vm,
                                 const char *alias)
{
    int i;

    if (STRPREFIX(alias, QEMU_DRIVE_HOST_PREFIX))
        alias += strlen(QEMU_DRIVE_HOST_PREFIX);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk;

        disk = vm->def->disks[i];
        if (disk->info.alias != NULL && STREQ(disk->info.alias, alias))
            return disk;
    }

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("no disk found with alias %s"),
                    alias);
    return NULL;
}

static int
qemuProcessGetVolumeQcowPassphrase(virConnectPtr conn,
                                   virDomainDiskDefPtr disk,
                                   char **secretRet,
                                   size_t *secretLen)
{
    virSecretPtr secret;
    char *passphrase;
    unsigned char *data;
    size_t size;
    int ret = -1;
    virStorageEncryptionPtr enc;

    if (!disk->encryption) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("disk %s does not have any encryption information"),
                        disk->src);
        return -1;
    }
    enc = disk->encryption;

    if (!conn) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("cannot find secrets without a connection"));
        goto cleanup;
    }

    if (conn->secretDriver == NULL ||
        conn->secretDriver->lookupByUUID == NULL ||
        conn->secretDriver->getValue == NULL) {
        qemuReportError(VIR_ERR_NO_SUPPORT, "%s",
                        _("secret storage not supported"));
        goto cleanup;
    }

    if (enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_QCOW ||
        enc->nsecrets != 1 ||
        enc->secrets[0]->type !=
        VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE) {
        qemuReportError(VIR_ERR_XML_ERROR,
                        _("invalid <encryption> for volume %s"), disk->src);
        goto cleanup;
    }

    secret = conn->secretDriver->lookupByUUID(conn,
                                              enc->secrets[0]->uuid);
    if (secret == NULL)
        goto cleanup;
    data = conn->secretDriver->getValue(secret, &size,
                                        VIR_SECRET_GET_VALUE_INTERNAL_CALL);
    virUnrefSecret(secret);
    if (data == NULL)
        goto cleanup;

    if (memchr(data, '\0', size) != NULL) {
        memset(data, 0, size);
        VIR_FREE(data);
        qemuReportError(VIR_ERR_XML_ERROR,
                        _("format='qcow' passphrase for %s must not contain a "
                          "'\\0'"), disk->src);
        goto cleanup;
    }

    if (VIR_ALLOC_N(passphrase, size + 1) < 0) {
        memset(data, 0, size);
        VIR_FREE(data);
        virReportOOMError();
        goto cleanup;
    }
    memcpy(passphrase, data, size);
    passphrase[size] = '\0';

    memset(data, 0, size);
    VIR_FREE(data);

    *secretRet = passphrase;
    *secretLen = size;

    ret = 0;

cleanup:
    return ret;
}

static int
qemuProcessFindVolumeQcowPassphrase(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    virDomainObjPtr vm,
                                    const char *path,
                                    char **secretRet,
                                    size_t *secretLen)
{
    virDomainDiskDefPtr disk;
    int ret = -1;

    virDomainObjLock(vm);
    disk = qemuProcessFindDomainDiskByPath(vm, path);

    if (!disk)
        goto cleanup;

    ret = qemuProcessGetVolumeQcowPassphrase(conn, disk, secretRet, secretLen);

cleanup:
    virDomainObjUnlock(vm);
    return ret;
}


static int
qemuProcessHandleReset(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                       virDomainObjPtr vm)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr event;

    virDomainObjLock(vm);
    event = virDomainEventRebootNewFromObj(vm);
    virDomainObjUnlock(vm);

    if (event) {
        qemuDriverLock(driver);
        qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }

    return 0;
}


static int
qemuProcessHandleShutdown(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm)
{
    virDomainObjLock(vm);
    ((qemuDomainObjPrivatePtr) vm->privateData)->gotShutdown = true;
    virDomainObjUnlock(vm);

    return 0;
}


static int
qemuProcessHandleStop(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                      virDomainObjPtr vm)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr event = NULL;

    virDomainObjLock(vm);
    if (vm->state == VIR_DOMAIN_RUNNING) {
        VIR_DEBUG("Transitioned guest %s to paused state due to unknown event",
                  vm->def->name);

        vm->state = VIR_DOMAIN_PAUSED;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);

        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0) {
            VIR_WARN("Unable to save status on vm %s after state change",
                     vm->def->name);
        }
    }
    virDomainObjUnlock(vm);

    if (event) {
        qemuDriverLock(driver);
        if (event)
            qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }

    return 0;
}


static int
qemuProcessHandleRTCChange(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                           virDomainObjPtr vm,
                           long long offset)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr event;

    virDomainObjLock(vm);
    event = virDomainEventRTCChangeNewFromObj(vm, offset);

    if (vm->def->clock.offset == VIR_DOMAIN_CLOCK_OFFSET_VARIABLE)
        vm->def->clock.data.adjustment = offset;

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        VIR_WARN0("unable to save domain status with RTC change");

    virDomainObjUnlock(vm);

    if (event) {
        qemuDriverLock(driver);
        qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }

    return 0;
}


static int
qemuProcessHandleWatchdog(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm,
                          int action)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr watchdogEvent = NULL;
    virDomainEventPtr lifecycleEvent = NULL;

    virDomainObjLock(vm);
    watchdogEvent = virDomainEventWatchdogNewFromObj(vm, action);

    if (action == VIR_DOMAIN_EVENT_WATCHDOG_PAUSE &&
        vm->state == VIR_DOMAIN_RUNNING) {
        VIR_DEBUG("Transitioned guest %s to paused state due to watchdog", vm->def->name);

        vm->state = VIR_DOMAIN_PAUSED;
        lifecycleEvent = virDomainEventNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG);

        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0) {
            VIR_WARN("Unable to save status on vm %s after watchdog event",
                     vm->def->name);
        }
    }

    if (vm->def->watchdog->action == VIR_DOMAIN_WATCHDOG_ACTION_DUMP) {
        struct qemuDomainWatchdogEvent *wdEvent;
        if (VIR_ALLOC(wdEvent) == 0) {
            wdEvent->action = VIR_DOMAIN_WATCHDOG_ACTION_DUMP;
            wdEvent->vm = vm;
            /* Hold an extra reference because we can't allow 'vm' to be
             * deleted before handling watchdog event is finished.
             */
            virDomainObjRef(vm);
            if (virThreadPoolSendJob(driver->workerPool, wdEvent) < 0) {
                if (virDomainObjUnref(vm) == 0)
                    vm = NULL;
                VIR_FREE(wdEvent);
            }
        } else {
            virReportOOMError();
        }
    }

    if (vm)
        virDomainObjUnlock(vm);

    if (watchdogEvent || lifecycleEvent) {
        qemuDriverLock(driver);
        if (watchdogEvent)
            qemuDomainEventQueue(driver, watchdogEvent);
        if (lifecycleEvent)
            qemuDomainEventQueue(driver, lifecycleEvent);
        qemuDriverUnlock(driver);
    }

    return 0;
}


static int
qemuProcessHandleIOError(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                         virDomainObjPtr vm,
                         const char *diskAlias,
                         int action,
                         const char *reason)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr ioErrorEvent = NULL;
    virDomainEventPtr ioErrorEvent2 = NULL;
    virDomainEventPtr lifecycleEvent = NULL;
    const char *srcPath;
    const char *devAlias;
    virDomainDiskDefPtr disk;

    virDomainObjLock(vm);
    disk = qemuProcessFindDomainDiskByAlias(vm, diskAlias);

    if (disk) {
        srcPath = disk->src;
        devAlias = disk->info.alias;
    } else {
        srcPath = "";
        devAlias = "";
    }

    ioErrorEvent = virDomainEventIOErrorNewFromObj(vm, srcPath, devAlias, action);
    ioErrorEvent2 = virDomainEventIOErrorReasonNewFromObj(vm, srcPath, devAlias, action, reason);

    if (action == VIR_DOMAIN_EVENT_IO_ERROR_PAUSE &&
        vm->state == VIR_DOMAIN_RUNNING) {
        VIR_DEBUG("Transitioned guest %s to paused state due to IO error", vm->def->name);

        vm->state = VIR_DOMAIN_PAUSED;
        lifecycleEvent = virDomainEventNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_IOERROR);

        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
            VIR_WARN("Unable to save status on vm %s after IO error", vm->def->name);
    }
    virDomainObjUnlock(vm);

    if (ioErrorEvent || ioErrorEvent2 || lifecycleEvent) {
        qemuDriverLock(driver);
        if (ioErrorEvent)
            qemuDomainEventQueue(driver, ioErrorEvent);
        if (ioErrorEvent2)
            qemuDomainEventQueue(driver, ioErrorEvent2);
        if (lifecycleEvent)
            qemuDomainEventQueue(driver, lifecycleEvent);
        qemuDriverUnlock(driver);
    }

    return 0;
}


static int
qemuProcessHandleGraphics(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm,
                          int phase,
                          int localFamily,
                          const char *localNode,
                          const char *localService,
                          int remoteFamily,
                          const char *remoteNode,
                          const char *remoteService,
                          const char *authScheme,
                          const char *x509dname,
                          const char *saslUsername)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr event;
    virDomainEventGraphicsAddressPtr localAddr = NULL;
    virDomainEventGraphicsAddressPtr remoteAddr = NULL;
    virDomainEventGraphicsSubjectPtr subject = NULL;
    int i;

    if (VIR_ALLOC(localAddr) < 0)
        goto no_memory;
    localAddr->family = localFamily;
    if (!(localAddr->service = strdup(localService)) ||
        !(localAddr->node = strdup(localNode)))
        goto no_memory;

    if (VIR_ALLOC(remoteAddr) < 0)
        goto no_memory;
    remoteAddr->family = remoteFamily;
    if (!(remoteAddr->service = strdup(remoteService)) ||
        !(remoteAddr->node = strdup(remoteNode)))
        goto no_memory;

    if (VIR_ALLOC(subject) < 0)
        goto no_memory;
    if (x509dname) {
        if (VIR_REALLOC_N(subject->identities, subject->nidentity+1) < 0)
            goto no_memory;
        subject->nidentity++;
        if (!(subject->identities[subject->nidentity-1].type = strdup("x509dname")) ||
            !(subject->identities[subject->nidentity-1].name = strdup(x509dname)))
            goto no_memory;
    }
    if (saslUsername) {
        if (VIR_REALLOC_N(subject->identities, subject->nidentity+1) < 0)
            goto no_memory;
        subject->nidentity++;
        if (!(subject->identities[subject->nidentity-1].type = strdup("saslUsername")) ||
            !(subject->identities[subject->nidentity-1].name = strdup(saslUsername)))
            goto no_memory;
    }

    virDomainObjLock(vm);
    event = virDomainEventGraphicsNewFromObj(vm, phase, localAddr, remoteAddr, authScheme, subject);
    virDomainObjUnlock(vm);

    if (event) {
        qemuDriverLock(driver);
        qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }

    return 0;

no_memory:
    virReportOOMError();
    if (localAddr) {
        VIR_FREE(localAddr->service);
        VIR_FREE(localAddr->node);
        VIR_FREE(localAddr);
    }
    if (remoteAddr) {
        VIR_FREE(remoteAddr->service);
        VIR_FREE(remoteAddr->node);
        VIR_FREE(remoteAddr);
    }
    if (subject) {
        for (i = 0 ; i < subject->nidentity ; i++) {
            VIR_FREE(subject->identities[i].type);
            VIR_FREE(subject->identities[i].name);
        }
        VIR_FREE(subject->identities);
        VIR_FREE(subject);
    }

    return -1;
}


static void qemuProcessHandleMonitorDestroy(qemuMonitorPtr mon,
                                            virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv;

    virDomainObjLock(vm);
    priv = vm->privateData;
    if (priv->mon == mon)
        priv->mon = NULL;
    if (virDomainObjUnref(vm) > 0)
        virDomainObjUnlock(vm);
}

static qemuMonitorCallbacks monitorCallbacks = {
    .destroy = qemuProcessHandleMonitorDestroy,
    .eofNotify = qemuProcessHandleMonitorEOF,
    .diskSecretLookup = qemuProcessFindVolumeQcowPassphrase,
    .domainShutdown = qemuProcessHandleShutdown,
    .domainStop = qemuProcessHandleStop,
    .domainReset = qemuProcessHandleReset,
    .domainRTCChange = qemuProcessHandleRTCChange,
    .domainWatchdog = qemuProcessHandleWatchdog,
    .domainIOError = qemuProcessHandleIOError,
    .domainGraphics = qemuProcessHandleGraphics,
};

static int
qemuConnectMonitor(struct qemud_driver *driver, virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (virSecurityManagerSetSocketLabel(driver->securityManager, vm) < 0) {
        VIR_ERROR(_("Failed to set security context for monitor for %s"),
                  vm->def->name);
        goto error;
    }

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted while the monitor is active */
    virDomainObjRef(vm);

    priv->mon = qemuMonitorOpen(vm,
                                priv->monConfig,
                                priv->monJSON,
                                &monitorCallbacks);

    /* Safe to ignore value since ref count was incremented above */
    if (priv->mon == NULL)
        ignore_value(virDomainObjUnref(vm));

    if (virSecurityManagerClearSocketLabel(driver->securityManager, vm) < 0) {
        VIR_ERROR(_("Failed to clear security context for monitor for %s"),
                  vm->def->name);
        goto error;
    }

    if (priv->mon == NULL) {
        VIR_INFO("Failed to connect monitor for %s", vm->def->name);
        goto error;
    }


    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorSetCapabilities(priv->mon);
    qemuDomainObjExitMonitorWithDriver(driver, vm);

error:

    return ret;
}

static int
qemuProcessLogFD(struct qemud_driver *driver, const char* name, bool append)
{
    char *logfile;
    mode_t logmode;
    int fd = -1;

    if (virAsprintf(&logfile, "%s/%s.log", driver->logDir, name) < 0) {
        virReportOOMError();
        return -1;
    }

    logmode = O_CREAT | O_WRONLY;
    /* Only logrotate files in /var/log, so only append if running privileged */
    if (driver->privileged || append)
        logmode |= O_APPEND;
    else
        logmode |= O_TRUNC;

    if ((fd = open(logfile, logmode, S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("failed to create logfile %s"),
                             logfile);
        VIR_FREE(logfile);
        return -1;
    }
    VIR_FREE(logfile);
    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set VM logfile close-on-exec flag"));
        VIR_FORCE_CLOSE(fd);
        return -1;
    }
    return fd;
}


static int
qemuProcessLogReadFD(const char* logDir, const char* name, off_t pos)
{
    char *logfile;
    mode_t logmode = O_RDONLY;
    int fd = -1;

    if (virAsprintf(&logfile, "%s/%s.log", logDir, name) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("failed to build logfile name %s/%s.log"),
                        logDir, name);
        return -1;
    }

    if ((fd = open(logfile, logmode)) < 0) {
        virReportSystemError(errno,
                             _("failed to create logfile %s"),
                             logfile);
        VIR_FREE(logfile);
        return -1;
    }
    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set VM logfile close-on-exec flag"));
        VIR_FORCE_CLOSE(fd);
        VIR_FREE(logfile);
        return -1;
    }
    if (pos < 0 || lseek(fd, pos, SEEK_SET) < 0) {
        virReportSystemError(pos < 0 ? 0 : errno,
                             _("Unable to seek to %lld in %s"),
                             (long long) pos, logfile);
        VIR_FORCE_CLOSE(fd);
    }
    VIR_FREE(logfile);
    return fd;
}


typedef int qemuProcessLogHandleOutput(virDomainObjPtr vm,
                                       const char *output,
                                       int fd);

/*
 * Returns -1 for error, 0 on success
 */
static int
qemuProcessReadLogOutput(virDomainObjPtr vm,
                         int fd,
                         char *buf,
                         size_t buflen,
                         qemuProcessLogHandleOutput func,
                         const char *what,
                         int timeout)
{
    int retries = (timeout*10);
    int got = 0;
    char *debug = NULL;
    int ret = -1;
    char *filter_next = buf;

    buf[0] = '\0';

    /* This relies on log message format generated by virLogFormatString() and
     * might need to be modified when message format changes. */
    if (virAsprintf(&debug, ": %d: debug : ", vm->pid) < 0) {
        virReportOOMError();
        return -1;
    }

    while (retries) {
        ssize_t func_ret, bytes;
        int isdead = 0;
        char *eol;

        func_ret = func(vm, buf, fd);

        if (kill(vm->pid, 0) == -1 && errno == ESRCH)
            isdead = 1;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        bytes = saferead(fd, buf+got, buflen-got-1);
        if (bytes < 0) {
            virReportSystemError(errno,
                                 _("Failure while reading %s log output"),
                                 what);
            goto cleanup;
        }

        got += bytes;
        buf[got] = '\0';

        /* Filter out debug messages from intermediate libvirt process */
        while ((eol = strchr(filter_next, '\n'))) {
            *eol = '\0';
            if (strstr(filter_next, debug)) {
                memmove(filter_next, eol + 1, got - (eol - buf));
                got -= eol + 1 - filter_next;
            } else {
                filter_next = eol + 1;
                *eol = '\n';
            }
        }

        if (got == buflen-1) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Out of space while reading %s log output: %s"),
                            what, buf);
            goto cleanup;
        }

        if (isdead) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Process exited while reading %s log output: %s"),
                            what, buf);
            goto cleanup;
        }

        if (func_ret <= 0) {
            ret = func_ret;
            goto cleanup;
        }

        usleep(100*1000);
        retries--;
    }

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Timed out while reading %s log output: %s"),
                    what, buf);

cleanup:
    VIR_FREE(debug);
    return ret;
}


/*
 * Look at a chunk of data from the QEMU stdout logs and try to
 * find a TTY device, as indicated by a line like
 *
 * char device redirected to /dev/pts/3
 *
 * Returns -1 for error, 0 success, 1 continue reading
 */
static int
qemuProcessExtractTTYPath(const char *haystack,
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
                virReportOOMError();
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
qemuProcessLookupPTYs(virDomainChrDefPtr *devices,
                      int count,
                      const char *prefix,
                      virHashTablePtr paths)
{
    int i;

    for (i = 0 ; i < count ; i++) {
        virDomainChrDefPtr chr = devices[i];
        if (chr->source.type == VIR_DOMAIN_CHR_TYPE_PTY) {
            char id[16];
            const char *path;

            if (snprintf(id, sizeof(id), "%s%d", prefix, i) >= sizeof(id))
                return -1;

            path = (const char *) virHashLookup(paths, id);
            if (path == NULL) {
                if (chr->source.data.file.path == NULL) {
                    /* neither the log output nor 'info chardev' had a
                     * pty path for this chardev, report an error
                     */
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    _("no assigned pty for device %s"), id);
                    return -1;
                } else {
                    /* 'info chardev' had no pty path for this chardev,
                     * but the log output had, so we're fine
                     */
                    continue;
                }
            }

            VIR_FREE(chr->source.data.file.path);
            chr->source.data.file.path = strdup(path);

            if (chr->source.data.file.path == NULL) {
                virReportOOMError();
                return -1;
            }
        }
    }

    return 0;
}

static int
qemuProcessFindCharDevicePTYsMonitor(virDomainObjPtr vm,
                                     virHashTablePtr paths)
{
    if (qemuProcessLookupPTYs(vm->def->serials, vm->def->nserials,
                              "serial", paths) < 0)
        return -1;

    if (qemuProcessLookupPTYs(vm->def->parallels, vm->def->nparallels,
                              "parallel", paths) < 0)
        return -1;

    if (qemuProcessLookupPTYs(vm->def->channels, vm->def->nchannels,
                              "channel", paths) < 0)
        return -1;

    if (vm->def->console &&
        qemuProcessLookupPTYs(&vm->def->console, 1, "console", paths) < 0)
        return -1;

    return 0;
}

static int
qemuProcessFindCharDevicePTYs(virDomainObjPtr vm,
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
        if (chr->source.type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemuProcessExtractTTYPath(output, &offset,
                                                 &chr->source.data.file.path)) != 0)
                return ret;
        }
    }

    /* then the parallel devices */
    for (i = 0 ; i < vm->def->nparallels ; i++) {
        virDomainChrDefPtr chr = vm->def->parallels[i];
        if (chr->source.type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemuProcessExtractTTYPath(output, &offset,
                                                 &chr->source.data.file.path)) != 0)
                return ret;
        }
    }

    /* then the channel devices */
    for (i = 0 ; i < vm->def->nchannels ; i++) {
        virDomainChrDefPtr chr = vm->def->channels[i];
        if (chr->source.type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemuProcessExtractTTYPath(output, &offset,
                                                 &chr->source.data.file.path)) != 0)
                return ret;
        }
    }

    return 0;
}

static void qemuProcessFreePtyPath(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(payload);
}

static void
qemuProcessReadLogFD(int logfd, char *buf, int maxlen, int off)
{
    int ret;
    char *tmpbuf = buf + off;

    ret = saferead(logfd, tmpbuf, maxlen - off - 1);
    if (ret < 0) {
        ret = 0;
    }

    tmpbuf[ret] = '\0';
}

static int
qemuProcessWaitForMonitor(struct qemud_driver* driver,
                          virDomainObjPtr vm, off_t pos)
{
    char *buf;
    size_t buf_size = 4096; /* Plenty of space to get startup greeting */
    int logfd;
    int ret = -1;
    virHashTablePtr paths = NULL;
    qemuDomainObjPrivatePtr priv;

    if ((logfd = qemuProcessLogReadFD(driver->logDir, vm->def->name, pos)) < 0)
        return -1;

    if (VIR_ALLOC_N(buf, buf_size) < 0) {
        virReportOOMError();
        return -1;
    }

    if (qemuProcessReadLogOutput(vm, logfd, buf, buf_size,
                                 qemuProcessFindCharDevicePTYs,
                                 "console", 30) < 0)
        goto closelog;

    VIR_DEBUG("Connect monitor to %p '%s'", vm, vm->def->name);
    if (qemuConnectMonitor(driver, vm) < 0) {
        goto cleanup;
    }

    /* Try to get the pty path mappings again via the monitor. This is much more
     * reliable if it's available.
     * Note that the monitor itself can be on a pty, so we still need to try the
     * log output method. */
    paths = virHashCreate(0, qemuProcessFreePtyPath);
    if (paths == NULL)
        goto cleanup;

    priv = vm->privateData;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorGetPtyPaths(priv->mon, paths);
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    VIR_DEBUG("qemuMonitorGetPtyPaths returned %i", ret);
    if (ret == 0)
        ret = qemuProcessFindCharDevicePTYsMonitor(vm, paths);

cleanup:
    virHashFree(paths);

    if (kill(vm->pid, 0) == -1 && errno == ESRCH) {
        /* VM is dead, any other error raised in the interim is probably
         * not as important as the qemu cmdline output */
        qemuProcessReadLogFD(logfd, buf, buf_size, strlen(buf));
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("process exited while connecting to monitor: %s"),
                        buf);
        ret = -1;
    }

    VIR_FREE(buf);

closelog:
    if (VIR_CLOSE(logfd) < 0) {
        char ebuf[1024];
        VIR_WARN("Unable to close logfile: %s",
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    return ret;
}

static int
qemuProcessDetectVcpuPIDs(struct qemud_driver *driver,
                          virDomainObjPtr vm)
{
    pid_t *cpupids = NULL;
    int ncpupids;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (vm->def->virtType != VIR_DOMAIN_VIRT_KVM) {
        priv->nvcpupids = 1;
        if (VIR_ALLOC_N(priv->vcpupids, priv->nvcpupids) < 0) {
            virReportOOMError();
            return -1;
        }
        priv->vcpupids[0] = vm->pid;
        return 0;
    }

    /* What follows is now all KVM specific */

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if ((ncpupids = qemuMonitorGetCPUInfo(priv->mon, &cpupids)) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        return -1;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    /* Treat failure to get VCPU<->PID mapping as non-fatal */
    if (ncpupids == 0)
        return 0;

    if (ncpupids != vm->def->vcpus) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("got wrong number of vCPU pids from QEMU monitor. "
                          "got %d, wanted %d"),
                        ncpupids, vm->def->vcpus);
        VIR_FREE(cpupids);
        return -1;
    }

    priv->nvcpupids = ncpupids;
    priv->vcpupids = cpupids;
    return 0;
}

/*
 * To be run between fork/exec of QEMU only
 */
static int
qemuProcessInitCpuAffinity(virDomainObjPtr vm)
{
    int i, hostcpus, maxcpu = QEMUD_CPUMASK_LEN;
    virNodeInfo nodeinfo;
    unsigned char *cpumap;
    int cpumaplen;

    VIR_DEBUG0("Setting CPU affinity");

    if (nodeGetInfo(NULL, &nodeinfo) < 0)
        return -1;

    /* setaffinity fails if you set bits for CPUs which
     * aren't present, so we have to limit ourselves */
    hostcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    if (VIR_ALLOC_N(cpumap, cpumaplen) < 0) {
        virReportOOMError();
        return -1;
    }

    if (vm->def->cpumask) {
        /* XXX why don't we keep 'cpumask' in the libvirt cpumap
         * format to start with ?!?! */
        for (i = 0 ; i < maxcpu && i < vm->def->cpumasklen ; i++)
            if (vm->def->cpumask[i])
                VIR_USE_CPU(cpumap, i);
    } else {
        /* You may think this is redundant, but we can't assume libvirtd
         * itself is running on all pCPUs, so we need to explicitly set
         * the spawned QEMU instance to all pCPUs if no map is given in
         * its config file */
        for (i = 0 ; i < maxcpu ; i++)
            VIR_USE_CPU(cpumap, i);
    }

    /* We are pressuming we are running between fork/exec of QEMU
     * so use '0' to indicate our own process ID. No threads are
     * running at this point
     */
    if (virProcessInfoSetAffinity(0, /* Self */
                                  cpumap, cpumaplen, maxcpu) < 0) {
        VIR_FREE(cpumap);
        return -1;
    }
    VIR_FREE(cpumap);

    return 0;
}

/* Set CPU affinites for vcpus if vcpupin xml provided. */
static int
qemuProcessSetVcpuAffinites(virConnectPtr conn,
                            virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    virNodeInfo nodeinfo;
    pid_t vcpupid;
    unsigned char *cpumask;
    int vcpu, cpumaplen, hostcpus, maxcpu;

    if (virNodeGetInfo(conn, &nodeinfo) != 0) {
        return  -1;
    }

    if (!def->cputune.nvcpupin)
        return 0;

    if (priv->vcpupids == NULL) {
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        "%s", _("cpu affinity is not supported"));
        return -1;
    }

    hostcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    cpumaplen = VIR_CPU_MAPLEN(hostcpus);
    maxcpu = cpumaplen * 8;

    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    for (vcpu = 0; vcpu < def->cputune.nvcpupin; vcpu++) {
        if (vcpu != def->cputune.vcpupin[vcpu]->vcpuid)
            continue;

        int i;
        unsigned char *cpumap = NULL;

        if (VIR_ALLOC_N(cpumap, cpumaplen) < 0) {
            virReportOOMError();
            return -1;
        }

        cpumask = (unsigned char *)def->cputune.vcpupin[vcpu]->cpumask;
        vcpupid = priv->vcpupids[vcpu];

        /* Convert cpumask to bitmap here. */
        for (i = 0; i < VIR_DOMAIN_CPUMASK_LEN; i++) {
            int cur = 0;
            int mod = 0;

            if (i) {
                cur = i / 8;
                mod = i % 8;
            }

            if (cpumask[i])
                cpumap[cur] |= 1 << mod;
        }

        if (virProcessInfoSetAffinity(vcpupid,
                                      cpumap,
                                      cpumaplen,
                                      maxcpu) < 0) {
            return -1;
        }
    }

    return 0;
}

static int
qemuProcessInitPasswords(virConnectPtr conn,
                         struct qemud_driver *driver,
                         virDomainObjPtr vm,
                         virBitmapPtr qemuCaps)
{
    int ret = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (vm->def->ngraphics == 1) {
        if (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            ret = qemuDomainChangeGraphicsPasswords(driver, vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_VNC,
                                                    &vm->def->graphics[0]->data.vnc.auth,
                                                    driver->vncPassword);
        } else if (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            ret = qemuDomainChangeGraphicsPasswords(driver, vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
                                                    &vm->def->graphics[0]->data.spice.auth,
                                                    driver->spicePassword);
        }
    }

    if (ret < 0)
        goto cleanup;

    if (qemuCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        int i;

        for (i = 0 ; i < vm->def->ndisks ; i++) {
            char *secret;
            size_t secretLen;
            const char *alias;

            if (!vm->def->disks[i]->encryption ||
                !vm->def->disks[i]->src)
                continue;

            if (qemuProcessGetVolumeQcowPassphrase(conn,
                                                   vm->def->disks[i],
                                                   &secret, &secretLen) < 0)
                goto cleanup;

            alias = vm->def->disks[i]->info.alias;
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            ret = qemuMonitorSetDrivePassphrase(priv->mon, alias, secret);
            VIR_FREE(secret);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (ret < 0)
                goto cleanup;
        }
    }

cleanup:
    return ret;
}


#define QEMU_PCI_VENDOR_INTEL     0x8086
#define QEMU_PCI_VENDOR_LSI_LOGIC 0x1000
#define QEMU_PCI_VENDOR_REDHAT    0x1af4
#define QEMU_PCI_VENDOR_CIRRUS    0x1013
#define QEMU_PCI_VENDOR_REALTEK   0x10ec
#define QEMU_PCI_VENDOR_AMD       0x1022
#define QEMU_PCI_VENDOR_ENSONIQ   0x1274
#define QEMU_PCI_VENDOR_VMWARE    0x15ad
#define QEMU_PCI_VENDOR_QEMU      0x1234

#define QEMU_PCI_PRODUCT_DISK_VIRTIO 0x1001

#define QEMU_PCI_PRODUCT_BALLOON_VIRTIO 0x1002

#define QEMU_PCI_PRODUCT_NIC_NE2K     0x8029
#define QEMU_PCI_PRODUCT_NIC_PCNET    0x2000
#define QEMU_PCI_PRODUCT_NIC_RTL8139  0x8139
#define QEMU_PCI_PRODUCT_NIC_E1000    0x100E
#define QEMU_PCI_PRODUCT_NIC_VIRTIO   0x1000

#define QEMU_PCI_PRODUCT_VGA_CIRRUS 0x00b8
#define QEMU_PCI_PRODUCT_VGA_VMWARE 0x0405
#define QEMU_PCI_PRODUCT_VGA_STDVGA 0x1111

#define QEMU_PCI_PRODUCT_AUDIO_AC97    0x2415
#define QEMU_PCI_PRODUCT_AUDIO_ES1370  0x5000

#define QEMU_PCI_PRODUCT_CONTROLLER_PIIX 0x7010
#define QEMU_PCI_PRODUCT_CONTROLLER_LSI  0x0012

#define QEMU_PCI_PRODUCT_WATCHDOG_I63000ESB 0x25ab

static int
qemuProcessAssignNextPCIAddress(virDomainDeviceInfo *info,
                                int vendor,
                                int product,
                                qemuMonitorPCIAddress *addrs,
                                int naddrs)
{
    int found = 0;
    int i;

    VIR_DEBUG("Look for %x:%x out of %d", vendor, product, naddrs);

    for (i = 0 ; (i < naddrs) && !found; i++) {
        VIR_DEBUG("Maybe %x:%x", addrs[i].vendor, addrs[i].product);
        if (addrs[i].vendor == vendor &&
            addrs[i].product == product) {
            VIR_DEBUG("Match %d", i);
            found = 1;
            break;
        }
    }
    if (!found) {
        return -1;
    }

    /* Blank it out so this device isn't matched again */
    addrs[i].vendor = 0;
    addrs[i].product = 0;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        info->addr.pci.domain = addrs[i].addr.domain;
        info->addr.pci.bus = addrs[i].addr.bus;
        info->addr.pci.slot = addrs[i].addr.slot;
        info->addr.pci.function = addrs[i].addr.function;
    }

    return 0;
}

static int
qemuProcessGetPCIDiskVendorProduct(virDomainDiskDefPtr def,
                                   unsigned *vendor,
                                   unsigned *product)
{
    switch (def->bus) {
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        *vendor = QEMU_PCI_VENDOR_REDHAT;
        *product = QEMU_PCI_PRODUCT_DISK_VIRTIO;
        break;

    default:
        return -1;
    }

    return 0;
}

static int
qemuProcessGetPCINetVendorProduct(virDomainNetDefPtr def,
                                  unsigned *vendor,
                                  unsigned *product)
{
    if (!def->model)
        return -1;

    if (STREQ(def->model, "ne2k_pci")) {
        *vendor = QEMU_PCI_VENDOR_REALTEK;
        *product = QEMU_PCI_PRODUCT_NIC_NE2K;
    } else if (STREQ(def->model, "pcnet")) {
        *vendor = QEMU_PCI_VENDOR_AMD;
        *product = QEMU_PCI_PRODUCT_NIC_PCNET;
    } else if (STREQ(def->model, "rtl8139")) {
        *vendor = QEMU_PCI_VENDOR_REALTEK;
        *product = QEMU_PCI_PRODUCT_NIC_RTL8139;
    } else if (STREQ(def->model, "e1000")) {
        *vendor = QEMU_PCI_VENDOR_INTEL;
        *product = QEMU_PCI_PRODUCT_NIC_E1000;
    } else if (STREQ(def->model, "virtio")) {
        *vendor = QEMU_PCI_VENDOR_REDHAT;
        *product = QEMU_PCI_PRODUCT_NIC_VIRTIO;
    } else {
        VIR_INFO("Unexpected NIC model %s, cannot get PCI address",
                 def->model);
        return -1;
    }
    return 0;
}

static int
qemuProcessGetPCIControllerVendorProduct(virDomainControllerDefPtr def,
                                         unsigned *vendor,
                                         unsigned *product)
{
    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        *vendor = QEMU_PCI_VENDOR_LSI_LOGIC;
        *product = QEMU_PCI_PRODUCT_CONTROLLER_LSI;
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
        /* XXX we could put in the ISA bridge address, but
           that's not technically the FDC's address */
        return -1;

    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
        *vendor = QEMU_PCI_VENDOR_INTEL;
        *product = QEMU_PCI_PRODUCT_CONTROLLER_PIIX;
        break;

    default:
        VIR_INFO("Unexpected controller type %s, cannot get PCI address",
                 virDomainControllerTypeToString(def->type));
        return -1;
    }

    return 0;
}

static int
qemuProcessGetPCIVideoVendorProduct(virDomainVideoDefPtr def,
                                    unsigned *vendor,
                                    unsigned *product)
{
    switch (def->type) {
    case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
        *vendor = QEMU_PCI_VENDOR_CIRRUS;
        *product = QEMU_PCI_PRODUCT_VGA_CIRRUS;
        break;

    case VIR_DOMAIN_VIDEO_TYPE_VGA:
        *vendor = QEMU_PCI_VENDOR_QEMU;
        *product = QEMU_PCI_PRODUCT_VGA_STDVGA;
        break;

    case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
        *vendor = QEMU_PCI_VENDOR_VMWARE;
        *product = QEMU_PCI_PRODUCT_VGA_VMWARE;
        break;

    default:
        return -1;
    }
    return 0;
}

static int
qemuProcessGetPCISoundVendorProduct(virDomainSoundDefPtr def,
                                    unsigned *vendor,
                                    unsigned *product)
{
    switch (def->model) {
    case VIR_DOMAIN_SOUND_MODEL_ES1370:
        *vendor = QEMU_PCI_VENDOR_ENSONIQ;
        *product = QEMU_PCI_PRODUCT_AUDIO_ES1370;
        break;

    case VIR_DOMAIN_SOUND_MODEL_AC97:
        *vendor = QEMU_PCI_VENDOR_INTEL;
        *product = QEMU_PCI_PRODUCT_AUDIO_AC97;
        break;

    default:
        return -1;
    }

    return 0;
}

static int
qemuProcessGetPCIWatchdogVendorProduct(virDomainWatchdogDefPtr def,
                                       unsigned *vendor,
                                       unsigned *product)
{
    switch (def->model) {
    case VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB:
        *vendor = QEMU_PCI_VENDOR_INTEL;
        *product = QEMU_PCI_PRODUCT_WATCHDOG_I63000ESB;
        break;

    default:
        return -1;
    }

    return 0;
}


static int
qemuProcessGetPCIMemballoonVendorProduct(virDomainMemballoonDefPtr def,
                                         unsigned *vendor,
                                         unsigned *product)
{
    switch (def->model) {
    case VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO:
        *vendor = QEMU_PCI_VENDOR_REDHAT;
        *product = QEMU_PCI_PRODUCT_BALLOON_VIRTIO;
        break;

    default:
        return -1;
    }

    return 0;
}


/*
 * This entire method assumes that PCI devices in 'info pci'
 * match ordering of devices specified on the command line
 * wrt to devices of matching vendor+product
 *
 * XXXX this might not be a valid assumption if we assign
 * some static addrs on CLI. Have to check that...
 */
static int
qemuProcessDetectPCIAddresses(virDomainObjPtr vm,
                              qemuMonitorPCIAddress *addrs,
                              int naddrs)
{
    unsigned int vendor = 0, product = 0;
    int i;

    /* XXX should all these vendor/product IDs be kept in the
     * actual device data structure instead ?
     */

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (qemuProcessGetPCIDiskVendorProduct(vm->def->disks[i], &vendor, &product) < 0)
            continue;

        if (qemuProcessAssignNextPCIAddress(&(vm->def->disks[i]->info),
                                            vendor, product,
                                            addrs, naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for VirtIO disk %s"),
                            vm->def->disks[i]->dst);
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->nnets ; i++) {
        if (qemuProcessGetPCINetVendorProduct(vm->def->nets[i], &vendor, &product) < 0)
            continue;

        if (qemuProcessAssignNextPCIAddress(&(vm->def->nets[i]->info),
                                            vendor, product,
                                            addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for %s NIC"),
                            vm->def->nets[i]->model);
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        if (qemuProcessGetPCIControllerVendorProduct(vm->def->controllers[i], &vendor, &product) < 0)
            continue;

        if (qemuProcessAssignNextPCIAddress(&(vm->def->controllers[i]->info),
                                            vendor, product,
                                            addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for controller %s"),
                            virDomainControllerTypeToString(vm->def->controllers[i]->type));
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->nvideos ; i++) {
        if (qemuProcessGetPCIVideoVendorProduct(vm->def->videos[i], &vendor, &product) < 0)
            continue;

        if (qemuProcessAssignNextPCIAddress(&(vm->def->videos[i]->info),
                                            vendor, product,
                                            addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for video adapter %s"),
                            virDomainVideoTypeToString(vm->def->videos[i]->type));
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->nsounds ; i++) {
        if (qemuProcessGetPCISoundVendorProduct(vm->def->sounds[i], &vendor, &product) < 0)
            continue;

        if (qemuProcessAssignNextPCIAddress(&(vm->def->sounds[i]->info),
                                    vendor, product,
                                     addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for sound adapter %s"),
                            virDomainSoundModelTypeToString(vm->def->sounds[i]->model));
            return -1;
        }
    }


    if (vm->def->watchdog &&
        qemuProcessGetPCIWatchdogVendorProduct(vm->def->watchdog, &vendor, &product) == 0) {
        if (qemuProcessAssignNextPCIAddress(&(vm->def->watchdog->info),
                                            vendor, product,
                                            addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for watchdog %s"),
                            virDomainWatchdogModelTypeToString(vm->def->watchdog->model));
            return -1;
        }
    }

    if (vm->def->memballoon &&
        qemuProcessGetPCIMemballoonVendorProduct(vm->def->memballoon, &vendor, &product) == 0) {
        if (qemuProcessAssignNextPCIAddress(&(vm->def->memballoon->info),
                                            vendor, product,
                                            addrs, naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for balloon %s"),
                            virDomainMemballoonModelTypeToString(vm->def->memballoon->model));
            return -1;
        }
    }

    /* XXX console (virtio) */


    /* ... and now things we don't have in our xml */

    /* XXX USB controller ? */

    /* XXX what about other PCI devices (ie bridges) */

    return 0;
}

static int
qemuProcessInitPCIAddresses(struct qemud_driver *driver,
                            virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int naddrs;
    int ret;
    qemuMonitorPCIAddress *addrs = NULL;

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    naddrs = qemuMonitorGetAllPCIAddresses(priv->mon,
                                           &addrs);
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    ret = qemuProcessDetectPCIAddresses(vm, addrs, naddrs);

    VIR_FREE(addrs);

    return ret;
}


static int qemuProcessNextFreePort(struct qemud_driver *driver,
                                   int startPort)
{
    int i;

    for (i = startPort ; i < QEMU_VNC_PORT_MAX; i++) {
        int fd;
        int reuse = 1;
        struct sockaddr_in addr;
        bool used = false;

        if (virBitmapGetBit(driver->reservedVNCPorts,
                            i - QEMU_VNC_PORT_MIN, &used) < 0)
            VIR_DEBUG("virBitmapGetBit failed on bit %d", i - QEMU_VNC_PORT_MIN);

        if (used)
            continue;

        addr.sin_family = AF_INET;
        addr.sin_port = htons(i);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse, sizeof(reuse)) < 0) {
            VIR_FORCE_CLOSE(fd);
            break;
        }

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            /* Not in use, lets grab it */
            VIR_FORCE_CLOSE(fd);
            /* Add port to bitmap of reserved ports */
            if (virBitmapSetBit(driver->reservedVNCPorts,
                                i - QEMU_VNC_PORT_MIN) < 0) {
                VIR_DEBUG("virBitmapSetBit failed on bit %d",
                          i - QEMU_VNC_PORT_MIN);
            }
            return i;
        }
        VIR_FORCE_CLOSE(fd);

        if (errno == EADDRINUSE) {
            /* In use, try next */
            continue;
        }
        /* Some other bad failure, get out.. */
        break;
    }
    return -1;
}


static void
qemuProcessReturnPort(struct qemud_driver *driver,
                      int port)
{
    if (port < QEMU_VNC_PORT_MIN)
        return;

    if (virBitmapClearBit(driver->reservedVNCPorts,
                          port - QEMU_VNC_PORT_MIN) < 0)
        VIR_DEBUG("Could not mark port %d as unused", port);
}


static int
qemuProcessPrepareChardevDevice(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                virDomainChrDefPtr dev,
                                void *opaque ATTRIBUTE_UNUSED)
{
    int fd;
    if (dev->source.type != VIR_DOMAIN_CHR_TYPE_FILE)
        return 0;

    if ((fd = open(dev->source.data.file.path,
                   O_CREAT | O_APPEND, S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to pre-create chardev file '%s'"),
                             dev->source.data.file.path);
        return -1;
    }

    VIR_FORCE_CLOSE(fd);

    return 0;
}


static int
qemuProcessLimits(struct qemud_driver *driver)
{
    if (driver->maxProcesses > 0) {
        struct rlimit rlim;

        rlim.rlim_cur = rlim.rlim_max = driver->maxProcesses;
        if (setrlimit(RLIMIT_NPROC, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit number of processes to %d"),
                                 driver->maxProcesses);
            return -1;
        }
    }

    return 0;
}


struct qemuProcessHookData {
    virConnectPtr conn;
    virDomainObjPtr vm;
    struct qemud_driver *driver;
};

static int qemuProcessHook(void *data)
{
    struct qemuProcessHookData *h = data;

    if (qemuProcessLimits(h->driver) < 0)
        return -1;

    /* This must take place before exec(), so that all QEMU
     * memory allocation is on the correct NUMA node
     */
    if (qemuAddToCgroup(h->driver, h->vm->def) < 0)
        return -1;

    /* This must be done after cgroup placement to avoid resetting CPU
     * affinity */
    if (qemuProcessInitCpuAffinity(h->vm) < 0)
        return -1;

    if (virSecurityManagerSetProcessLabel(h->driver->securityManager, h->vm) < 0)
        return -1;

    return 0;
}


int
qemuProcessPrepareMonitorChr(struct qemud_driver *driver,
                             virDomainChrSourceDefPtr monConfig,
                             const char *vm)
{
    monConfig->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monConfig->data.nix.listen = true;

    if (virAsprintf(&monConfig->data.nix.path, "%s/%s.monitor",
                    driver->libDir, vm) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


int
qemuProcessStartCPUs(struct qemud_driver *driver, virDomainObjPtr vm,
                     virConnectPtr conn)
{
    int ret;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorStartCPUs(priv->mon, conn);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (ret == 0) {
        vm->state = VIR_DOMAIN_RUNNING;
    }

    return ret;
}


int qemuProcessStopCPUs(struct qemud_driver *driver, virDomainObjPtr vm)
{
    int ret;
    int oldState = vm->state;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    vm->state = VIR_DOMAIN_PAUSED;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorStopCPUs(priv->mon);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (ret < 0) {
        vm->state = oldState;
    }
    return ret;
}



static int
qemuProcessFiltersInstantiate(virConnectPtr conn,
                              virDomainDefPtr def)
{
    int err = 0;
    int i;

    if (!conn)
        return 1;

    for (i = 0 ; i < def->nnets ; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if ((net->filter) && (net->ifname)) {
           if (virDomainConfNWFilterInstantiate(conn, net)) {
                err = 1;
                break;
            }
        }
    }

    return err;
}

struct qemuProcessReconnectData {
    virConnectPtr conn;
    struct qemud_driver *driver;
};
/*
 * Open an existing VM's monitor, re-detect VCPU threads
 * and re-reserve the security labels in use
 */
static void
qemuProcessReconnect(void *payload, const void *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr obj = payload;
    struct qemuProcessReconnectData *data = opaque;
    struct qemud_driver *driver = data->driver;
    qemuDomainObjPrivatePtr priv;
    virBitmapPtr qemuCaps = NULL;
    virConnectPtr conn = data->conn;

    virDomainObjLock(obj);

    VIR_DEBUG("Reconnect monitor to %p '%s'", obj, obj->def->name);

    priv = obj->privateData;

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted if qemuConnectMonitor() failed */
    virDomainObjRef(obj);

    /* XXX check PID liveliness & EXE path */
    if (qemuConnectMonitor(driver, obj) < 0)
        goto error;

    if (qemuUpdateActivePciHostdevs(driver, obj->def) < 0) {
        goto error;
    }

    /* XXX we should be persisting the original flags in the XML
     * not re-detecting them, since the binary may have changed
     * since launch time */
    if (qemuCapsExtractVersionInfo(obj->def->emulator, obj->def->os.arch,
                                   NULL,
                                   &qemuCaps) >= 0 &&
        qemuCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        priv->persistentAddrs = 1;

        if (!(priv->pciaddrs = qemuDomainPCIAddressSetCreate(obj->def)) ||
            qemuAssignDevicePCISlots(obj->def, priv->pciaddrs) < 0)
            goto error;
    }

    if (virSecurityManagerReserveLabel(driver->securityManager, obj) < 0)
        goto error;

    if (qemuProcessFiltersInstantiate(conn, obj->def))
        goto error;

    if (obj->def->id >= driver->nextvmid)
        driver->nextvmid = obj->def->id + 1;

    if (virDomainObjUnref(obj) > 0)
        virDomainObjUnlock(obj);

    qemuCapsFree(qemuCaps);
    return;

error:
    qemuCapsFree(qemuCaps);
    if (!virDomainObjIsActive(obj)) {
        if (virDomainObjUnref(obj) > 0)
            virDomainObjUnlock(obj);
        return;
    }

    if (virDomainObjUnref(obj) > 0) {
        /* We can't get the monitor back, so must kill the VM
         * to remove danger of it ending up running twice if
         * user tries to start it again later */
        qemuProcessStop(driver, obj, 0);
        if (!obj->persistent)
            virDomainRemoveInactive(&driver->domains, obj);
        else
            virDomainObjUnlock(obj);
    }
}

/**
 * qemuProcessReconnectAll
 *
 * Try to re-open the resources for live VMs that we care
 * about.
 */
void
qemuProcessReconnectAll(virConnectPtr conn, struct qemud_driver *driver)
{
    struct qemuProcessReconnectData data = {conn, driver};
    virHashForEach(driver->domains.objs, qemuProcessReconnect, &data);
}

int qemuProcessStart(virConnectPtr conn,
                     struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     const char *migrateFrom,
                     bool start_paused,
                     int stdin_fd,
                     const char *stdin_path,
                     enum virVMOperationType vmop)
{
    int ret;
    virBitmapPtr qemuCaps = NULL;
    off_t pos = -1;
    char ebuf[1024];
    char *pidfile = NULL;
    int logfile = -1;
    char *timestamp;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCommandPtr cmd = NULL;
    struct qemuProcessHookData hookData;
    unsigned long cur_balloon;

    hookData.conn = conn;
    hookData.vm = vm;
    hookData.driver = driver;

    VIR_DEBUG0("Beginning VM startup process");

    if (virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("VM is already active"));
        return -1;
    }

    /* Do this upfront, so any part of the startup process can add
     * runtime state to vm->def that won't be persisted. This let's us
     * report implicit runtime defaults in the XML, like vnc listen/socket
     */
    VIR_DEBUG0("Setting current domain def as transient");
    if (virDomainObjSetDefTransient(driver->caps, vm, true) < 0)
        goto cleanup;

    vm->def->id = driver->nextvmid++;

    /* Run an early hook to set-up missing devices */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml = virDomainDefFormat(vm->def, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                    VIR_HOOK_QEMU_OP_PREPARE, VIR_HOOK_SUBOP_BEGIN, NULL, xml);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup;
    }

    /* Must be run before security labelling */
    VIR_DEBUG0("Preparing host devices");
    if (qemuPrepareHostDevices(driver, vm->def) < 0)
        goto cleanup;

    VIR_DEBUG0("Preparing chr devices");
    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuProcessPrepareChardevDevice,
                               NULL) < 0)
        goto cleanup;

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    VIR_DEBUG0("Generating domain security label (if required)");
    if (virSecurityManagerGenLabel(driver->securityManager, vm) < 0) {
        qemuAuditSecurityLabel(vm, false);
        goto cleanup;
    }
    qemuAuditSecurityLabel(vm, true);

    VIR_DEBUG0("Generating setting domain security labels (if required)");
    if (virSecurityManagerSetAllLabel(driver->securityManager,
                                      vm, stdin_path) < 0)
        goto cleanup;

    if (stdin_fd != -1) {
        /* if there's an fd to migrate from, and it's a pipe, put the
         * proper security label on it
         */
        struct stat stdin_sb;

        VIR_DEBUG0("setting security label on pipe used for migration");

        if (fstat(stdin_fd, &stdin_sb) < 0) {
            virReportSystemError(errno,
                                 _("cannot stat fd %d"), stdin_fd);
            goto cleanup;
        }
        if (S_ISFIFO(stdin_sb.st_mode) &&
            virSecurityManagerSetFDLabel(driver->securityManager, vm, stdin_fd) < 0)
            goto cleanup;
    }

    /* Ensure no historical cgroup for this VM is lying around bogus
     * settings */
    VIR_DEBUG0("Ensuring no historical cgroup is lying around");
    qemuRemoveCgroup(driver, vm, 1);

    if (vm->def->ngraphics == 1) {
        if (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            !vm->def->graphics[0]->data.vnc.socket &&
            vm->def->graphics[0]->data.vnc.autoport) {
            int port = qemuProcessNextFreePort(driver, QEMU_VNC_PORT_MIN);
            if (port < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("Unable to find an unused VNC port"));
                goto cleanup;
            }
            vm->def->graphics[0]->data.vnc.port = port;
        } else if (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
                   vm->def->graphics[0]->data.spice.autoport) {
            int port = qemuProcessNextFreePort(driver, QEMU_VNC_PORT_MIN);
            int tlsPort = -1;
            if (port < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("Unable to find an unused SPICE port"));
                goto cleanup;
            }

            if (driver->spiceTLS) {
                tlsPort = qemuProcessNextFreePort(driver, port + 1);
                if (tlsPort < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("Unable to find an unused SPICE TLS port"));
                    qemuProcessReturnPort(driver, port);
                    goto cleanup;
                }
            }

            vm->def->graphics[0]->data.spice.port = port;
            vm->def->graphics[0]->data.spice.tlsPort = tlsPort;
        }
    }

    if (virFileMakePath(driver->logDir) != 0) {
        virReportSystemError(errno,
                             _("cannot create log directory %s"),
                             driver->logDir);
        goto cleanup;
    }

    VIR_DEBUG0("Creating domain log file");
    if ((logfile = qemuProcessLogFD(driver, vm->def->name, false)) < 0)
        goto cleanup;

    VIR_DEBUG0("Determining emulator version");
    if (qemuCapsExtractVersionInfo(vm->def->emulator, vm->def->os.arch,
                                   NULL,
                                   &qemuCaps) < 0)
        goto cleanup;

    VIR_DEBUG0("Setting up domain cgroup (if required)");
    if (qemuSetupCgroup(driver, vm) < 0)
        goto cleanup;

    if (VIR_ALLOC(priv->monConfig) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    VIR_DEBUG0("Preparing monitor state");
    if (qemuProcessPrepareMonitorChr(driver, priv->monConfig, vm->def->name) < 0)
        goto cleanup;

#if HAVE_YAJL
    if (qemuCapsGet(qemuCaps, QEMU_CAPS_MONITOR_JSON))
        priv->monJSON = 1;
    else
#endif
        priv->monJSON = 0;

    priv->monitor_warned = 0;
    priv->gotShutdown = false;

    if ((ret = virFileDeletePid(driver->stateDir, vm->def->name)) != 0) {
        virReportSystemError(ret,
                             _("Cannot remove stale PID file for %s"),
                             vm->def->name);
        goto cleanup;
    }

    if (!(pidfile = virFilePid(driver->stateDir, vm->def->name))) {
        virReportSystemError(errno,
                             "%s", _("Failed to build pidfile path."));
        goto cleanup;
    }

    /*
     * Normally PCI addresses are assigned in the virDomainCreate
     * or virDomainDefine methods. We might still need to assign
     * some here to cope with the question of upgrades. Regardless
     * we also need to populate the PCi address set cache for later
     * use in hotplug
     */
    if (qemuCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        VIR_DEBUG0("Assigning domain PCI addresses");
        /* Populate cache with current addresses */
        if (priv->pciaddrs) {
            qemuDomainPCIAddressSetFree(priv->pciaddrs);
            priv->pciaddrs = NULL;
        }
        if (!(priv->pciaddrs = qemuDomainPCIAddressSetCreate(vm->def)))
            goto cleanup;


        /* Assign any remaining addresses */
        if (qemuAssignDevicePCISlots(vm->def, priv->pciaddrs) < 0)
            goto cleanup;

        priv->persistentAddrs = 1;
    } else {
        priv->persistentAddrs = 0;
    }

    VIR_DEBUG0("Building emulator command line");
    if (!(cmd = qemuBuildCommandLine(conn, driver, vm->def, priv->monConfig,
                                     priv->monJSON != 0, qemuCaps,
                                     migrateFrom, stdin_fd,
                                     vm->current_snapshot, vmop)))
        goto cleanup;

#if 0
    /* XXX */
    if (qemuDomainSnapshotSetCurrentInactive(vm, driver->snapshotDir) < 0)
        goto cleanup;
#endif

    /* now that we know it is about to start call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml = virDomainDefFormat(vm->def, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                    VIR_HOOK_QEMU_OP_START, VIR_HOOK_SUBOP_BEGIN, NULL, xml);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup;
    }

    if ((timestamp = virTimestamp()) == NULL) {
        virReportOOMError();
        goto cleanup;
    } else {
        if (safewrite(logfile, timestamp, strlen(timestamp)) < 0 ||
            safewrite(logfile, START_POSTFIX, strlen(START_POSTFIX)) < 0) {
            VIR_WARN("Unable to write timestamp to logfile: %s",
                     virStrerror(errno, ebuf, sizeof ebuf));
        }

        VIR_FREE(timestamp);
    }

    virCommandWriteArgLog(cmd, logfile);

    if ((pos = lseek(logfile, 0, SEEK_END)) < 0)
        VIR_WARN("Unable to seek to end of logfile: %s",
                 virStrerror(errno, ebuf, sizeof ebuf));

    VIR_DEBUG("Clear emulator capabilities: %d",
              driver->clearEmulatorCapabilities);
    if (driver->clearEmulatorCapabilities)
        virCommandClearCaps(cmd);

    virCommandSetPreExecHook(cmd, qemuProcessHook, &hookData);

    virCommandSetOutputFD(cmd, &logfile);
    virCommandSetErrorFD(cmd, &logfile);
    virCommandNonblockingFDs(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    ret = virCommandRun(cmd, NULL);
    VIR_FREE(pidfile);

    /* wait for qemu process to show up */
    if (ret == 0) {
        if (virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Domain %s didn't show up"), vm->def->name);
            ret = -1;
        }
#if 0
    } else if (ret == -2) {
        /*
         * XXX this is bogus. It isn't safe to set vm->pid = child
         * because the child no longer exists.
         */

        /* The virExec process that launches the daemon failed. Pending on
         * when it failed (we can't determine for sure), there may be
         * extra info in the domain log (if the hook failed for example).
         *
         * Pretend like things succeeded, and let 'WaitForMonitor' report
         * the log contents for us.
         */
        vm->pid = child;
        ret = 0;
#endif
    }

    if (migrateFrom)
        start_paused = true;
    vm->state = start_paused ? VIR_DOMAIN_PAUSED : VIR_DOMAIN_RUNNING;

    if (ret == -1) /* The VM failed to start; tear filters before taps */
        virDomainConfVMNWFilterTeardown(vm);

    if (ret == -1) /* The VM failed to start */
        goto cleanup;

    VIR_DEBUG0("Waiting for monitor to show up");
    if (qemuProcessWaitForMonitor(driver, vm, pos) < 0)
        goto cleanup;

    VIR_DEBUG0("Detecting VCPU PIDs");
    if (qemuProcessDetectVcpuPIDs(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG0("Setting VCPU affinities");
    if (qemuProcessSetVcpuAffinites(conn, vm) < 0)
        goto cleanup;

    VIR_DEBUG0("Setting any required VM passwords");
    if (qemuProcessInitPasswords(conn, driver, vm, qemuCaps) < 0)
        goto cleanup;

    /* If we have -device, then addresses are assigned explicitly.
     * If not, then we have to detect dynamic ones here */
    if (!qemuCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        VIR_DEBUG0("Determining domain device PCI addresses");
        if (qemuProcessInitPCIAddresses(driver, vm) < 0)
            goto cleanup;
    }

    VIR_DEBUG0("Setting initial memory amount");
    cur_balloon = vm->def->mem.cur_balloon;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorSetBalloon(priv->mon, cur_balloon) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cleanup;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (!start_paused) {
        VIR_DEBUG0("Starting domain CPUs");
        /* Allow the CPUS to start executing */
        if (qemuProcessStartCPUs(driver, vm, conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("resume operation failed"));
            goto cleanup;
        }
    }


    VIR_DEBUG0("Writing domain status to disk");
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;

    qemuCapsFree(qemuCaps);
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(logfile);

    return 0;

cleanup:
    /* We jump here if we failed to start the VM for any reason, or
     * if we failed to initialize the now running VM. kill it off and
     * pretend we never started it */
    qemuCapsFree(qemuCaps);
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(logfile);
    qemuProcessStop(driver, vm, 0);

    return -1;
}


void qemuProcessStop(struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     int migrated)
{
    int ret;
    int retries = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virErrorPtr orig_err;
    virDomainDefPtr def;
    int i;
    int logfile = -1;
    char *timestamp;
    char ebuf[1024];

    VIR_DEBUG("Shutting down VM '%s' pid=%d migrated=%d",
              vm->def->name, vm->pid, migrated);

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("VM '%s' not active", vm->def->name);
        return;
    }

    if ((logfile = qemuProcessLogFD(driver, vm->def->name, true)) < 0) {
        /* To not break the normal domain shutdown process, skip the
         * timestamp log writing if failed on opening log file. */
        VIR_WARN("Unable to open logfile: %s",
                  virStrerror(errno, ebuf, sizeof ebuf));
    } else {
        if ((timestamp = virTimestamp()) == NULL) {
            virReportOOMError();
        } else {
            if (safewrite(logfile, timestamp, strlen(timestamp)) < 0 ||
                safewrite(logfile, SHUTDOWN_POSTFIX,
                          strlen(SHUTDOWN_POSTFIX)) < 0) {
                VIR_WARN("Unable to write timestamp to logfile: %s",
                         virStrerror(errno, ebuf, sizeof ebuf));
            }

            VIR_FREE(timestamp);
        }

        if (VIR_CLOSE(logfile) < 0)
             VIR_WARN("Unable to close logfile: %s",
                      virStrerror(errno, ebuf, sizeof ebuf));
    }

    /* This method is routinely used in clean up paths. Disable error
     * reporting so we don't squash a legit error. */
    orig_err = virSaveLastError();

    virDomainConfVMNWFilterTeardown(vm);

    if (driver->macFilter) {
        def = vm->def;
        for (i = 0 ; i < def->nnets ; i++) {
            virDomainNetDefPtr net = def->nets[i];
            if (net->ifname == NULL)
                continue;
            if ((errno = networkDisallowMacOnPort(driver, net->ifname,
                                                  net->mac))) {
                virReportSystemError(errno,
             _("failed to remove ebtables rule to allow MAC address on  '%s'"),
                                     net->ifname);
            }
        }
    }

    /* This will safely handle a non-running guest with pid=0 or pid=-1*/
    if (virKillProcess(vm->pid, 0) == 0 &&
        virKillProcess(vm->pid, SIGTERM) < 0)
        virReportSystemError(errno,
                             _("Failed to send SIGTERM to %s (%d)"),
                             vm->def->name, vm->pid);

    if (priv->mon)
        qemuMonitorClose(priv->mon);

    if (priv->monConfig) {
        if (priv->monConfig->type == VIR_DOMAIN_CHR_TYPE_UNIX)
            unlink(priv->monConfig->data.nix.path);
        virDomainChrSourceDefFree(priv->monConfig);
        priv->monConfig = NULL;
    }

    /* shut it off for sure */
    virKillProcess(vm->pid, SIGKILL);

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml = virDomainDefFormat(vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                    VIR_HOOK_QEMU_OP_STOPPED, VIR_HOOK_SUBOP_END, NULL, xml);
        VIR_FREE(xml);
    }

    /* Reset Security Labels */
    virSecurityManagerRestoreAllLabel(driver->securityManager,
                                      vm, migrated);
    virSecurityManagerReleaseLabel(driver->securityManager, vm);

    /* Clear out dynamically assigned labels */
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        VIR_FREE(vm->def->seclabel.model);
        VIR_FREE(vm->def->seclabel.label);
        VIR_FREE(vm->def->seclabel.imagelabel);
    }

    virDomainDefClearDeviceAliases(vm->def);
    if (!priv->persistentAddrs) {
        virDomainDefClearPCIAddresses(vm->def);
        qemuDomainPCIAddressSetFree(priv->pciaddrs);
        priv->pciaddrs = NULL;
    }

    qemuDomainReAttachHostDevices(driver, vm->def);

#if WITH_MACVTAP
    def = vm->def;
    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            delMacvtap(net->ifname, net->mac, net->data.direct.linkdev,
                       &net->data.direct.virtPortProfile);
            VIR_FREE(net->ifname);
        }
    }
#endif

retry:
    if ((ret = qemuRemoveCgroup(driver, vm, 0)) < 0) {
        if (ret == -EBUSY && (retries++ < 5)) {
            usleep(200*1000);
            goto retry;
        }
        VIR_WARN("Failed to remove cgroup for %s",
                 vm->def->name);
    }

    qemuProcessRemoveDomainStatus(driver, vm);

    /* Remove VNC port from port reservation bitmap, but only if it was
       reserved by the driver (autoport=yes)
    */
    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport) {
        qemuProcessReturnPort(driver, vm->def->graphics[0]->data.vnc.port);
    }
    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
        vm->def->graphics[0]->data.spice.autoport) {
        qemuProcessReturnPort(driver, vm->def->graphics[0]->data.spice.port);
        qemuProcessReturnPort(driver, vm->def->graphics[0]->data.spice.tlsPort);
    }

    vm->pid = -1;
    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;
    VIR_FREE(priv->vcpupids);
    priv->nvcpupids = 0;

    /* The "release" hook cleans up additional resources */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml = virDomainDefFormat(vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                    VIR_HOOK_QEMU_OP_RELEASE, VIR_HOOK_SUBOP_END, NULL, xml);
        VIR_FREE(xml);
    }

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
}
