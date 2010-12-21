/*
 * driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006, 2007, 2008, 2009, 2010 Red Hat, Inc.
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
#include <sys/time.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <paths.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/un.h>


#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "qemu_driver.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_command.h"
#include "qemu_cgroup.h"
#include "qemu_hostdev.h"
#include "qemu_hotplug.h"
#include "qemu_monitor.h"
#include "qemu_bridge_filter.h"
#include "qemu_audit.h"
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
#include "processinfo.h"
#include "qemu_security_stacked.h"
#include "qemu_security_dac.h"
#include "libvirt_internal.h"
#include "xml.h"
#include "cpu/cpu.h"
#include "macvtap.h"
#include "sysinfo.h"
#include "domain_nwfilter.h"
#include "hooks.h"
#include "storage_file.h"
#include "files.h"
#include "fdstream.h"
#include "configmake.h"
#include "threadpool.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define QEMU_VNC_PORT_MIN  5900
#define QEMU_VNC_PORT_MAX  65535

#define QEMU_NB_MEM_PARAM  3


#define timeval_to_ms(tv)       (((tv).tv_sec * 1000ull) + ((tv).tv_usec / 1000))

struct watchdogEvent
{
    virDomainObjPtr vm;
    int action;
};

static void processWatchdogEvent(void *data, void *opaque);

static int qemudShutdown(void);

static void qemuDomainEventFlush(int timer, void *opaque);
static void qemuDomainEventQueue(struct qemud_driver *driver,
                                 virDomainEventPtr event);

static int qemudDomainObjStart(virConnectPtr conn,
                               struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               bool start_paused);

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom,
                              bool start_paused,
                              int stdin_fd,
                              const char *stdin_path,
                              enum virVMOperationType vmop);

static void qemudShutdownVMDaemon(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  int migrated);

static int qemudDomainGetMaxVcpus(virDomainPtr dom);

static int qemuDetectVcpuPIDs(struct qemud_driver *driver,
                              virDomainObjPtr vm);

static int qemudVMFiltersInstantiate(virConnectPtr conn,
                                     virDomainDefPtr def);

static struct qemud_driver *qemu_driver = NULL;


static int doStartCPUs(struct qemud_driver *driver, virDomainObjPtr vm, virConnectPtr conn)
{
    int ret;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorStartCPUs(priv->mon, conn);
    if (ret == 0) {
        vm->state = VIR_DOMAIN_RUNNING;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    return ret;
}

static int doStopCPUs(struct qemud_driver *driver, virDomainObjPtr vm)
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
qemudLogFD(struct qemud_driver *driver, const char* name, bool append)
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
qemudLogReadFD(const char* logDir, const char* name, off_t pos)
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


struct qemuAutostartData {
    struct qemud_driver *driver;
    virConnectPtr conn;
};
static void
qemuAutostartDomain(void *payload, const char *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr vm = payload;
    struct qemuAutostartData *data = opaque;
    virErrorPtr err;

    virDomainObjLock(vm);
    virResetLastError();
    if (qemuDomainObjBeginJobWithDriver(data->driver, vm) < 0) {
        err = virGetLastError();
        VIR_ERROR(_("Failed to start job on VM '%s': %s"),
                  vm->def->name,
                  err ? err->message : _("unknown error"));
    } else {
        if (vm->autostart &&
            !virDomainObjIsActive(vm) &&
            qemudDomainObjStart(data->conn, data->driver, vm, false) < 0) {
            err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : _("unknown error"));
        }

        if (qemuDomainObjEndJob(vm) == 0)
            vm = NULL;
    }

    if (vm)
        virDomainObjUnlock(vm);
}

static void
qemudAutostartConfigs(struct qemud_driver *driver) {
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen(driver->privileged ?
                                        "qemu:///system" :
                                        "qemu:///session");
    /* Ignoring NULL conn which is mostly harmless here */
    struct qemuAutostartData data = { driver, conn };

    qemuDriverLock(driver);
    virHashForEach(driver->domains.objs, qemuAutostartDomain, &data);
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
qemudRemoveDomainStatus(struct qemud_driver *driver,
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


/*
 * This is a callback registered with a qemuMonitorPtr  instance,
 * and to be invoked when the monitor console hits an end of file
 * condition, or error, thus indicating VM shutdown should be
 * performed
 */
static void
qemuHandleMonitorEOF(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                     virDomainObjPtr vm,
                     int hasError) {
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;

    VIR_DEBUG("Received EOF on %p '%s'", vm, vm->def->name);

    virDomainObjLock(vm);

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

    qemudShutdownVMDaemon(driver, vm, 0);
    qemuDomainStopAudit(vm, hasError ? "failed" : "shutdown");

    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains, vm);
    else
        virDomainObjUnlock(vm);

    if (event) {
        qemuDriverLock(driver);
        qemuDomainEventQueue(driver, event);
        qemuDriverUnlock(driver);
    }
}


static virDomainDiskDefPtr
findDomainDiskByPath(virDomainObjPtr vm,
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
findDomainDiskByAlias(virDomainObjPtr vm,
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
getVolumeQcowPassphrase(virConnectPtr conn,
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
        qemuReportError(VIR_ERR_INVALID_DOMAIN,
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
        qemuReportError(VIR_ERR_INVALID_SECRET,
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
findVolumeQcowPassphrase(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                         virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *path,
                         char **secretRet,
                         size_t *secretLen)
{
    virDomainDiskDefPtr disk;
    int ret = -1;

    virDomainObjLock(vm);
    disk = findDomainDiskByPath(vm, path);

    if (!disk)
        goto cleanup;

    ret = getVolumeQcowPassphrase(conn, disk, secretRet, secretLen);

cleanup:
    virDomainObjUnlock(vm);
    return ret;
}


static int
qemuHandleDomainReset(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
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
qemuHandleDomainShutdown(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                         virDomainObjPtr vm)
{
    virDomainObjLock(vm);
    ((qemuDomainObjPrivatePtr) vm->privateData)->gotShutdown = true;
    virDomainObjUnlock(vm);

    return 0;
}


static int
qemuHandleDomainStop(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                     virDomainObjPtr vm)
{
    struct qemud_driver *driver = qemu_driver;
    virDomainEventPtr event = NULL;

    virDomainObjLock(vm);
    if (vm->state == VIR_DOMAIN_RUNNING) {
        VIR_DEBUG("Transitioned guest %s to paused state due to unknown event", vm->def->name);

        vm->state = VIR_DOMAIN_PAUSED;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);

        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
            VIR_WARN("Unable to save status on vm %s after IO error", vm->def->name);
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
qemuHandleDomainRTCChange(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
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
qemuHandleDomainWatchdog(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
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

        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
            VIR_WARN("Unable to save status on vm %s after IO error", vm->def->name);
    }

    if (vm->def->watchdog->action == VIR_DOMAIN_WATCHDOG_ACTION_DUMP) {
        struct watchdogEvent *wdEvent;
        if (VIR_ALLOC(wdEvent) == 0) {
            wdEvent->action = VIR_DOMAIN_WATCHDOG_ACTION_DUMP;
            wdEvent->vm = vm;
            ignore_value(virThreadPoolSendJob(driver->workerPool, wdEvent));
        } else
            virReportOOMError();
    }

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
qemuHandleDomainIOError(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
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
    disk = findDomainDiskByAlias(vm, diskAlias);

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
qemuHandleDomainGraphics(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
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

    virDomainObjLock(vm);

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
        if (!(subject->identities[subject->nidentity].type = strdup("x509dname")) ||
            !(subject->identities[subject->nidentity].name = strdup(x509dname)))
            goto no_memory;
        subject->nidentity++;
    }
    if (saslUsername) {
        if (VIR_REALLOC_N(subject->identities, subject->nidentity+1) < 0)
            goto no_memory;
        if (!(subject->identities[subject->nidentity].type = strdup("saslUsername")) ||
            !(subject->identities[subject->nidentity].name = strdup(saslUsername)))
            goto no_memory;
        subject->nidentity++;
    }

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


static void qemuHandleMonitorDestroy(qemuMonitorPtr mon,
                                     virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    if (priv->mon == mon)
        priv->mon = NULL;
    virDomainObjUnref(vm);
}

static qemuMonitorCallbacks monitorCallbacks = {
    .destroy = qemuHandleMonitorDestroy,
    .eofNotify = qemuHandleMonitorEOF,
    .diskSecretLookup = findVolumeQcowPassphrase,
    .domainShutdown = qemuHandleDomainShutdown,
    .domainStop = qemuHandleDomainStop,
    .domainReset = qemuHandleDomainReset,
    .domainRTCChange = qemuHandleDomainRTCChange,
    .domainWatchdog = qemuHandleDomainWatchdog,
    .domainIOError = qemuHandleDomainIOError,
    .domainGraphics = qemuHandleDomainGraphics,
};

static int
qemuConnectMonitor(struct qemud_driver *driver, virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecuritySocketLabel &&
        driver->securityDriver->domainSetSecuritySocketLabel
          (driver->securityDriver,vm) < 0) {
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

    if (priv->mon == NULL)
        virDomainObjUnref(vm);

    if (driver->securityDriver &&
        driver->securityDriver->domainClearSecuritySocketLabel &&
        driver->securityDriver->domainClearSecuritySocketLabel
          (driver->securityDriver,vm) < 0) {
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
    if (ret < 0)
        qemuMonitorClose(priv->mon);

    return ret;
}

struct virReconnectDomainData {
    virConnectPtr conn;
    struct qemud_driver *driver;
};
/*
 * Open an existing VM's monitor, re-detect VCPU threads
 * and re-reserve the security labels in use
 */
static void
qemuReconnectDomain(void *payload, const char *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr obj = payload;
    struct virReconnectDomainData *data = opaque;
    struct qemud_driver *driver = data->driver;
    qemuDomainObjPrivatePtr priv;
    unsigned long long qemuCmdFlags;
    virConnectPtr conn = data->conn;

    virDomainObjLock(obj);

    VIR_DEBUG("Reconnect monitor to %p '%s'", obj, obj->def->name);

    priv = obj->privateData;

    /* XXX check PID liveliness & EXE path */
    if (qemuConnectMonitor(driver, obj) < 0)
        goto error;

    if (qemuUpdateActivePciHostdevs(driver, obj->def) < 0) {
        goto error;
    }

    /* XXX we should be persisting the original flags in the XML
     * not re-detecting them, since the binary may have changed
     * since launch time */
    if (qemuCapsExtractVersionInfo(obj->def->emulator,
                                   NULL,
                                   &qemuCmdFlags) >= 0 &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        priv->persistentAddrs = 1;

        if (!(priv->pciaddrs = qemuDomainPCIAddressSetCreate(obj->def)) ||
            qemuAssignDevicePCISlots(obj->def, priv->pciaddrs) < 0)
            goto error;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainReserveSecurityLabel &&
        driver->securityDriver->domainReserveSecurityLabel(driver->securityDriver,
                                                           obj) < 0)
        goto error;

    if (qemudVMFiltersInstantiate(conn, obj->def))
        goto error;

    if (obj->def->id >= driver->nextvmid)
        driver->nextvmid = obj->def->id + 1;

    virDomainObjUnlock(obj);
    return;

error:
    /* We can't get the monitor back, so must kill the VM
     * to remove danger of it ending up running twice if
     * user tries to start it again later */
    qemudShutdownVMDaemon(driver, obj, 0);
    if (!obj->persistent)
        virDomainRemoveInactive(&driver->domains, obj);
    else
        virDomainObjUnlock(obj);
}

/**
 * qemudReconnectDomains
 *
 * Try to re-open the resources for live VMs that we care
 * about.
 */
static void
qemuReconnectDomains(virConnectPtr conn, struct qemud_driver *driver)
{
    struct virReconnectDomainData data = {conn, driver};
    virHashForEach(driver->domains.objs, qemuReconnectDomain, &data);
}


static int
qemudSecurityInit(struct qemud_driver *qemud_drv)
{
    int ret;
    virSecurityDriverPtr security_drv;

    qemuSecurityStackedSetDriver(qemud_drv);
    qemuSecurityDACSetDriver(qemud_drv);

    ret = virSecurityDriverStartup(&security_drv,
                                   qemud_drv->securityDriverName,
                                   qemud_drv->allowDiskFormatProbing);
    if (ret == -1) {
        VIR_ERROR0(_("Failed to start security driver"));
        return -1;
    }

    /* No primary security driver wanted to be enabled: just setup
     * the DAC driver on its own */
    if (ret == -2) {
        qemud_drv->securityDriver = &qemuDACSecurityDriver;
        VIR_INFO0(_("No security driver available"));
    } else {
        qemud_drv->securityPrimaryDriver = security_drv;
        qemud_drv->securitySecondaryDriver = &qemuDACSecurityDriver;
        qemud_drv->securityDriver = &qemuStackedSecurityDriver;
        VIR_INFO("Initialized security driver %s", security_drv->name);
    }

    return 0;
}


static virCapsPtr
qemuCreateCapabilities(virCapsPtr oldcaps,
                       struct qemud_driver *driver)
{
    virCapsPtr caps;

    /* Basic host arch / guest machine capabilities */
    if (!(caps = qemuCapsInit(oldcaps))) {
        virReportOOMError();
        return NULL;
    }

    if (driver->allowDiskFormatProbing) {
        caps->defaultDiskDriverName = NULL;
        caps->defaultDiskDriverType = NULL;
    } else {
        caps->defaultDiskDriverName = "qemu";
        caps->defaultDiskDriverType = "raw";
    }

    qemuDomainSetPrivateDataHooks(caps);
    qemuDomainSetNamespaceHooks(caps);

    if (virGetHostUUID(caps->host.host_uuid)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot get the host uuid"));
        goto err_exit;
    }

    /* Security driver data */
    if (driver->securityPrimaryDriver) {
        const char *doi, *model;

        doi = virSecurityDriverGetDOI(driver->securityPrimaryDriver);
        model = virSecurityDriverGetModel(driver->securityPrimaryDriver);

        if (!(caps->host.secModel.model = strdup(model)))
            goto no_memory;
        if (!(caps->host.secModel.doi = strdup(doi)))
            goto no_memory;

        VIR_DEBUG("Initialized caps for security driver \"%s\" with "
                  "DOI \"%s\"", model, doi);
    }

    return caps;

no_memory:
    virReportOOMError();
err_exit:
    virCapabilitiesFree(caps);
    return NULL;
}

static void qemuDomainSnapshotLoad(void *payload,
                                   const char *name ATTRIBUTE_UNUSED,
                                   void *data)
{
    virDomainObjPtr vm = (virDomainObjPtr)payload;
    char *baseDir = (char *)data;
    char *snapDir = NULL;
    DIR *dir = NULL;
    struct dirent *entry;
    char *xmlStr;
    int ret;
    char *fullpath;
    virDomainSnapshotDefPtr def = NULL;
    char ebuf[1024];

    virDomainObjLock(vm);
    if (virAsprintf(&snapDir, "%s/%s", baseDir, vm->def->name) < 0) {
        VIR_ERROR(_("Failed to allocate memory for snapshot directory for domain %s"),
                   vm->def->name);
        goto cleanup;
    }

    VIR_INFO("Scanning for snapshots for domain %s in %s", vm->def->name,
             snapDir);

    if (!(dir = opendir(snapDir))) {
        if (errno != ENOENT)
            VIR_ERROR(_("Failed to open snapshot directory %s for domain %s: %s"),
                      snapDir, vm->def->name,
                      virStrerror(errno, ebuf, sizeof(ebuf)));
        goto cleanup;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        VIR_INFO("Loading snapshot file '%s'", entry->d_name);

        if (virAsprintf(&fullpath, "%s/%s", snapDir, entry->d_name) < 0) {
            VIR_ERROR0(_("Failed to allocate memory for path"));
            continue;
        }

        ret = virFileReadAll(fullpath, 1024*1024*1, &xmlStr);
        if (ret < 0) {
            /* Nothing we can do here, skip this one */
            VIR_ERROR(_("Failed to read snapshot file %s: %s"), fullpath,
                      virStrerror(errno, ebuf, sizeof(ebuf)));
            VIR_FREE(fullpath);
            continue;
        }

        def = virDomainSnapshotDefParseString(xmlStr, 0);
        if (def == NULL) {
            /* Nothing we can do here, skip this one */
            VIR_ERROR(_("Failed to parse snapshot XML from file '%s'"), fullpath);
            VIR_FREE(fullpath);
            VIR_FREE(xmlStr);
            continue;
        }

        virDomainSnapshotAssignDef(&vm->snapshots, def);

        VIR_FREE(fullpath);
        VIR_FREE(xmlStr);
    }

    /* FIXME: qemu keeps internal track of snapshots.  We can get access
     * to this info via the "info snapshots" monitor command for running
     * domains, or via "qemu-img snapshot -l" for shutoff domains.  It would
     * be nice to update our internal state based on that, but there is a
     * a problem.  qemu doesn't track all of the same metadata that we do.
     * In particular we wouldn't be able to fill in the <parent>, which is
     * pretty important in our metadata.
     */

    virResetLastError();

cleanup:
    if (dir)
        closedir(dir);
    VIR_FREE(snapDir);
    virDomainObjUnlock(vm);
}

/**
 * qemudStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
qemudStartup(int privileged) {
    char *base = NULL;
    char *driverConf = NULL;
    int rc;
    virConnectPtr conn = NULL;

    if (VIR_ALLOC(qemu_driver) < 0)
        return -1;

    if (virMutexInit(&qemu_driver->lock) < 0) {
        VIR_ERROR0(_("cannot initialize mutex"));
        VIR_FREE(qemu_driver);
        return -1;
    }
    qemuDriverLock(qemu_driver);
    qemu_driver->privileged = privileged;

    /* Don't have a dom0 so start from 1 */
    qemu_driver->nextvmid = 1;

    if (virDomainObjListInit(&qemu_driver->domains) < 0)
        goto out_of_memory;

    /* Init callback list */
    if (VIR_ALLOC(qemu_driver->domainEventCallbacks) < 0)
        goto out_of_memory;
    if (!(qemu_driver->domainEventQueue = virDomainEventQueueNew()))
        goto out_of_memory;

    if ((qemu_driver->domainEventTimer =
         virEventAddTimeout(-1, qemuDomainEventFlush, qemu_driver, NULL)) < 0)
        goto error;

    /* Allocate bitmap for vnc port reservation */
    if ((qemu_driver->reservedVNCPorts =
         virBitmapAlloc(QEMU_VNC_PORT_MAX - QEMU_VNC_PORT_MIN)) == NULL)
        goto out_of_memory;

    /* read the host sysinfo */
    if (privileged)
        qemu_driver->hostsysinfo = virSysinfoRead();

    if (privileged) {
        if (virAsprintf(&qemu_driver->logDir,
                        "%s/log/libvirt/qemu", LOCALSTATEDIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONFDIR "/libvirt")) == NULL)
            goto out_of_memory;

        if (virAsprintf(&qemu_driver->stateDir,
                      "%s/run/libvirt/qemu", LOCALSTATEDIR) == -1)
            goto out_of_memory;

        if (virAsprintf(&qemu_driver->libDir,
                      "%s/lib/libvirt/qemu", LOCALSTATEDIR) == -1)
            goto out_of_memory;

        if (virAsprintf(&qemu_driver->cacheDir,
                      "%s/cache/libvirt/qemu", LOCALSTATEDIR) == -1)
            goto out_of_memory;
        if (virAsprintf(&qemu_driver->saveDir,
                      "%s/lib/libvirt/qemu/save", LOCALSTATEDIR) == -1)
            goto out_of_memory;
        if (virAsprintf(&qemu_driver->snapshotDir,
                        "%s/lib/libvirt/qemu/snapshot", LOCALSTATEDIR) == -1)
            goto out_of_memory;
        if (virAsprintf(&qemu_driver->autoDumpPath,
                        "%s/lib/libvirt/qemu/dump", LOCALSTATEDIR) == -1)
            goto out_of_memory;
    } else {
        uid_t uid = geteuid();
        char *userdir = virGetUserDirectory(uid);
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
        if (virAsprintf(&qemu_driver->saveDir, "%s/qemu/save", base) == -1)
            goto out_of_memory;
        if (virAsprintf(&qemu_driver->snapshotDir, "%s/qemu/snapshot", base) == -1)
            goto out_of_memory;
        if (virAsprintf(&qemu_driver->autoDumpPath, "%s/qemu/dump", base) == -1)
            goto out_of_memory;
    }

    if (virFileMakePath(qemu_driver->stateDir) != 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create state dir '%s': %s"),
                  qemu_driver->stateDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->libDir) != 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create lib dir '%s': %s"),
                  qemu_driver->libDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->cacheDir) != 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create cache dir '%s': %s"),
                  qemu_driver->cacheDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->saveDir) != 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create save dir '%s': %s"),
                  qemu_driver->saveDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->snapshotDir) != 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create save dir '%s': %s"),
                  qemu_driver->snapshotDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->autoDumpPath) != 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create dump dir '%s': %s"),
                  qemu_driver->autoDumpPath, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }

    /* Configuration paths are either ~/.libvirt/qemu/... (session) or
     * /etc/libvirt/qemu/... (system).
     */
    if (virAsprintf(&driverConf, "%s/qemu.conf", base) < 0 ||
        virAsprintf(&qemu_driver->configDir, "%s/qemu", base) < 0 ||
        virAsprintf(&qemu_driver->autostartDir, "%s/qemu/autostart", base) < 0)
        goto out_of_memory;

    VIR_FREE(base);

    rc = virCgroupForDriver("qemu", &qemu_driver->cgroup, privileged, 1);
    if (rc < 0) {
        char buf[1024];
        VIR_WARN("Unable to create cgroup for driver: %s",
                 virStrerror(-rc, buf, sizeof(buf)));
    }

    if (qemudLoadDriverConfig(qemu_driver, driverConf) < 0) {
        goto error;
    }
    VIR_FREE(driverConf);

    if (qemudSecurityInit(qemu_driver) < 0)
        goto error;

    if ((qemu_driver->caps = qemuCreateCapabilities(NULL,
                                                    qemu_driver)) == NULL)
        goto error;

    if ((qemu_driver->activePciHostdevs = pciDeviceListNew()) == NULL)
        goto error;

    if (privileged) {
        if (chown(qemu_driver->libDir, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to user %d:%d"),
                                 qemu_driver->libDir, qemu_driver->user, qemu_driver->group);
            goto error;
        }
        if (chown(qemu_driver->cacheDir, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 qemu_driver->cacheDir, qemu_driver->user, qemu_driver->group);
            goto error;
        }
        if (chown(qemu_driver->saveDir, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 qemu_driver->saveDir, qemu_driver->user, qemu_driver->group);
            goto error;
        }
        if (chown(qemu_driver->snapshotDir, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 qemu_driver->snapshotDir, qemu_driver->user, qemu_driver->group);
            goto error;
        }
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
            virReportSystemError(rc,
                                 _("unable to create hugepage path %s"), mempath);
            VIR_FREE(mempath);
            goto error;
        }
        if (qemu_driver->privileged &&
            chown(mempath, qemu_driver->user, qemu_driver->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership on %s to %d:%d"),
                                 mempath, qemu_driver->user, qemu_driver->group);
            VIR_FREE(mempath);
            goto error;
        }

        qemu_driver->hugepage_path = mempath;
    }

    /* Get all the running persistent or transient configs first */
    if (virDomainLoadAllConfigs(qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->stateDir,
                                NULL,
                                1, NULL, NULL) < 0)
        goto error;

    conn = virConnectOpen(qemu_driver->privileged ?
                          "qemu:///system" :
                          "qemu:///session");

    qemuReconnectDomains(conn, qemu_driver);

    /* Then inactive persistent configs */
    if (virDomainLoadAllConfigs(qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->configDir,
                                qemu_driver->autostartDir,
                                0, NULL, NULL) < 0)
        goto error;


    virHashForEach(qemu_driver->domains.objs, qemuDomainSnapshotLoad,
                   qemu_driver->snapshotDir);

    qemuDriverUnlock(qemu_driver);

    qemudAutostartConfigs(qemu_driver);

    qemu_driver->workerPool = virThreadPoolNew(0, 1, processWatchdogEvent, qemu_driver);
    if (!qemu_driver->workerPool)
        goto error;

    if (conn)
        virConnectClose(conn);

    return 0;

out_of_memory:
    virReportOOMError();
error:
    if (qemu_driver)
        qemuDriverUnlock(qemu_driver);
    if (conn)
        virConnectClose(conn);
    VIR_FREE(base);
    VIR_FREE(driverConf);
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
    virDomainLoadAllConfigs(qemu_driver->caps,
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
    int active = 0;

    if (!qemu_driver)
        return 0;

    /* XXX having to iterate here is not great because it requires many locks */
    qemuDriverLock(qemu_driver);
    active = virDomainObjListNumOfDomains(&qemu_driver->domains, 1);
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
    int i;

    if (!qemu_driver)
        return -1;

    qemuDriverLock(qemu_driver);
    pciDeviceListFree(qemu_driver->activePciHostdevs);
    virCapabilitiesFree(qemu_driver->caps);

    virDomainObjListDeinit(&qemu_driver->domains);
    virBitmapFree(qemu_driver->reservedVNCPorts);

    virSysinfoDefFree(qemu_driver->hostsysinfo);

    VIR_FREE(qemu_driver->configDir);
    VIR_FREE(qemu_driver->autostartDir);
    VIR_FREE(qemu_driver->logDir);
    VIR_FREE(qemu_driver->stateDir);
    VIR_FREE(qemu_driver->libDir);
    VIR_FREE(qemu_driver->cacheDir);
    VIR_FREE(qemu_driver->saveDir);
    VIR_FREE(qemu_driver->snapshotDir);
    VIR_FREE(qemu_driver->autoDumpPath);
    VIR_FREE(qemu_driver->vncTLSx509certdir);
    VIR_FREE(qemu_driver->vncListen);
    VIR_FREE(qemu_driver->vncPassword);
    VIR_FREE(qemu_driver->vncSASLdir);
    VIR_FREE(qemu_driver->spiceTLSx509certdir);
    VIR_FREE(qemu_driver->spiceListen);
    VIR_FREE(qemu_driver->spicePassword);
    VIR_FREE(qemu_driver->hugetlbfs_mount);
    VIR_FREE(qemu_driver->hugepage_path);
    VIR_FREE(qemu_driver->securityDriverName);
    VIR_FREE(qemu_driver->saveImageFormat);
    VIR_FREE(qemu_driver->dumpImageFormat);

    ebtablesContextFree(qemu_driver->ebtables);

    if (qemu_driver->cgroupDeviceACL) {
        for (i = 0 ; qemu_driver->cgroupDeviceACL[i] != NULL ; i++)
            VIR_FREE(qemu_driver->cgroupDeviceACL[i]);
        VIR_FREE(qemu_driver->cgroupDeviceACL);
    }

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
    virThreadPoolFree(qemu_driver->workerPool);
    VIR_FREE(qemu_driver);

    return 0;
}

typedef int qemuLogHandleOutput(virDomainObjPtr vm,
                                const char *output,
                                int fd);

/*
 * Returns -1 for error, 0 on success
 */
static int
qemudReadLogOutput(virDomainObjPtr vm,
                   int fd,
                   char *buf,
                   size_t buflen,
                   qemuLogHandleOutput func,
                   const char *what,
                   int timeout)
{
    int retries = (timeout*10);
    int got = 0;
    buf[0] = '\0';

    while (retries) {
        ssize_t func_ret, ret;
        int isdead = 0;

        func_ret = func(vm, buf, fd);

        if (kill(vm->pid, 0) == -1 && errno == ESRCH)
            isdead = 1;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        ret = saferead(fd, buf+got, buflen-got-1);
        if (ret < 0) {
            virReportSystemError(errno,
                                 _("Failure while reading %s log output"),
                                 what);
            return -1;
        }

        got += ret;
        buf[got] = '\0';
        if (got == buflen-1) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Out of space while reading %s log output: %s"),
                            what, buf);
            return -1;
        }

        if (isdead) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Process exited while reading %s log output: %s"),
                            what, buf);
            return -1;
        }

        if (func_ret <= 0)
            return func_ret;

        usleep(100*1000);
        retries--;
    }

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Timed out while reading %s log output: %s"),
                    what, buf);
    return -1;
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
qemudExtractTTYPath(const char *haystack,
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
qemudFindCharDevicePTYsMonitor(virDomainObjPtr vm,
                               virHashTablePtr paths)
{
    int i;

#define LOOKUP_PTYS(array, arraylen, idprefix)                            \
    for (i = 0 ; i < (arraylen) ; i++) {                                  \
        virDomainChrDefPtr chr = (array)[i];                              \
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {                       \
            char id[16];                                                  \
                                                                          \
            if (snprintf(id, sizeof(id), idprefix "%i", i) >= sizeof(id)) \
                return -1;                                                \
                                                                          \
            const char *path = (const char *) virHashLookup(paths, id);   \
            if (path == NULL) {                                           \
                if (chr->data.file.path == NULL) {                        \
                    /* neither the log output nor 'info chardev' had a */ \
                    /* pty path for this chardev, report an error */      \
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,               \
                                    _("no assigned pty for device %s"), id); \
                    return -1;                                            \
                } else {                                                  \
                    /* 'info chardev' had no pty path for this chardev, */\
                    /* but the log output had, so we're fine */           \
                    continue;                                             \
                }                                                         \
            }                                                             \
                                                                          \
            VIR_FREE(chr->data.file.path);                                \
            chr->data.file.path = strdup(path);                           \
                                                                          \
            if (chr->data.file.path == NULL) {                            \
                virReportOOMError();                                      \
                return -1;                                                \
            }                                                             \
        }                                                                 \
    }

    LOOKUP_PTYS(vm->def->serials,   vm->def->nserials,   "serial");
    LOOKUP_PTYS(vm->def->parallels, vm->def->nparallels, "parallel");
    LOOKUP_PTYS(vm->def->channels,  vm->def->nchannels,  "channel");
    if (vm->def->console)
        LOOKUP_PTYS(&vm->def->console, 1,  "console");
#undef LOOKUP_PTYS

    return 0;
}

static int
qemudFindCharDevicePTYs(virDomainObjPtr vm,
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
            if ((ret = qemudExtractTTYPath(output, &offset,
                                           &chr->data.file.path)) != 0)
                return ret;
        }
    }

    /* then the parallel devices */
    for (i = 0 ; i < vm->def->nparallels ; i++) {
        virDomainChrDefPtr chr = vm->def->parallels[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractTTYPath(output, &offset,
                                           &chr->data.file.path)) != 0)
                return ret;
        }
    }

    /* then the channel devices */
    for (i = 0 ; i < vm->def->nchannels ; i++) {
        virDomainChrDefPtr chr = vm->def->channels[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractTTYPath(output, &offset,
                                           &chr->data.file.path)) != 0)
                return ret;
        }
    }

    return 0;
}

static void qemudFreePtyPath(void *payload, const char *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(payload);
}

static void
qemuReadLogFD(int logfd, char *buf, int maxlen, int off)
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
qemudWaitForMonitor(struct qemud_driver* driver,
                    virDomainObjPtr vm, off_t pos)
{
    char buf[4096] = ""; /* Plenty of space to get startup greeting */
    int logfd;
    int ret = -1;
    virHashTablePtr paths = NULL;

    if ((logfd = qemudLogReadFD(driver->logDir, vm->def->name, pos)) < 0)
        return -1;

    if (qemudReadLogOutput(vm, logfd, buf, sizeof(buf),
                           qemudFindCharDevicePTYs,
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
    paths = virHashCreate(0);
    if (paths == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    ret = qemuMonitorGetPtyPaths(priv->mon, paths);
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    VIR_DEBUG("qemuMonitorGetPtyPaths returned %i", ret);
    if (ret == 0) {
        ret = qemudFindCharDevicePTYsMonitor(vm, paths);
    }

cleanup:
    if (paths) {
        virHashFree(paths, qemudFreePtyPath);
    }

    if (kill(vm->pid, 0) == -1 && errno == ESRCH) {
        /* VM is dead, any other error raised in the interim is probably
         * not as important as the qemu cmdline output */
        qemuReadLogFD(logfd, buf, sizeof(buf), strlen(buf));
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("process exited while connecting to monitor: %s"),
                        buf);
        ret = -1;
    }

closelog:
    if (VIR_CLOSE(logfd) < 0) {
        char ebuf[4096];
        VIR_WARN("Unable to close logfile: %s",
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    return ret;
}

static int
qemuDetectVcpuPIDs(struct qemud_driver *driver,
                   virDomainObjPtr vm) {
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
qemudInitCpuAffinity(virDomainObjPtr vm)
{
    int i, hostcpus, maxcpu = QEMUD_CPUMASK_LEN;
    virNodeInfo nodeinfo;
    unsigned char *cpumap;
    int cpumaplen;

    DEBUG0("Setting CPU affinity");

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


static int
qemuInitPasswords(virConnectPtr conn,
                  struct qemud_driver *driver,
                  virDomainObjPtr vm,
                  unsigned long long qemuCmdFlags) {
    int ret = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        (vm->def->graphics[0]->data.vnc.auth.passwd || driver->vncPassword)) {

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        ret = qemuMonitorSetVNCPassword(priv->mon,
                                        vm->def->graphics[0]->data.vnc.auth.passwd ?
                                        vm->def->graphics[0]->data.vnc.auth.passwd :
                                        driver->vncPassword);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

    if (ret < 0)
        goto cleanup;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        int i;

        for (i = 0 ; i < vm->def->ndisks ; i++) {
            char *secret;
            size_t secretLen;

            if (!vm->def->disks[i]->encryption ||
                !vm->def->disks[i]->src)
                continue;

            if (getVolumeQcowPassphrase(conn,
                                        vm->def->disks[i],
                                        &secret, &secretLen) < 0)
                goto cleanup;

            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            ret = qemuMonitorSetDrivePassphrase(priv->mon,
                                                vm->def->disks[i]->info.alias,
                                                secret);
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
qemuAssignNextPCIAddress(virDomainDeviceInfo *info,
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
qemuGetPCIDiskVendorProduct(virDomainDiskDefPtr def,
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
qemuGetPCINetVendorProduct(virDomainNetDefPtr def,
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
qemuGetPCIControllerVendorProduct(virDomainControllerDefPtr def,
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
qemuGetPCIVideoVendorProduct(virDomainVideoDefPtr def,
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
qemuGetPCISoundVendorProduct(virDomainSoundDefPtr def,
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
qemuGetPCIWatchdogVendorProduct(virDomainWatchdogDefPtr def,
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
qemuGetPCIMemballoonVendorProduct(virDomainMemballoonDefPtr def,
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
qemuDetectPCIAddresses(virDomainObjPtr vm,
                       qemuMonitorPCIAddress *addrs,
                       int naddrs)
{
    unsigned int vendor = 0, product = 0;
    int i;

    /* XXX should all these vendor/product IDs be kept in the
     * actual device data structure instead ?
     */

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (qemuGetPCIDiskVendorProduct(vm->def->disks[i], &vendor, &product) < 0)
            continue;

        if (qemuAssignNextPCIAddress(&(vm->def->disks[i]->info),
                                     vendor, product,
                                     addrs, naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for VirtIO disk %s"),
                            vm->def->disks[i]->dst);
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->nnets ; i++) {
        if (qemuGetPCINetVendorProduct(vm->def->nets[i], &vendor, &product) < 0)
            continue;

        if (qemuAssignNextPCIAddress(&(vm->def->nets[i]->info),
                                     vendor, product,
                                     addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for %s NIC"),
                            vm->def->nets[i]->model);
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        if (qemuGetPCIControllerVendorProduct(vm->def->controllers[i], &vendor, &product) < 0)
            continue;

        if (qemuAssignNextPCIAddress(&(vm->def->controllers[i]->info),
                                     vendor, product,
                                     addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for controller %s"),
                            virDomainControllerTypeToString(vm->def->controllers[i]->type));
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->nvideos ; i++) {
        if (qemuGetPCIVideoVendorProduct(vm->def->videos[i], &vendor, &product) < 0)
            continue;

        if (qemuAssignNextPCIAddress(&(vm->def->videos[i]->info),
                                     vendor, product,
                                     addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for video adapter %s"),
                            virDomainVideoTypeToString(vm->def->videos[i]->type));
            return -1;
        }
    }

    for (i = 0 ; i < vm->def->nsounds ; i++) {
        if (qemuGetPCISoundVendorProduct(vm->def->sounds[i], &vendor, &product) < 0)
            continue;

        if (qemuAssignNextPCIAddress(&(vm->def->sounds[i]->info),
                                    vendor, product,
                                     addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for sound adapter %s"),
                            virDomainSoundModelTypeToString(vm->def->sounds[i]->model));
            return -1;
        }
    }


    if (vm->def->watchdog &&
        qemuGetPCIWatchdogVendorProduct(vm->def->watchdog, &vendor, &product) == 0) {
        if (qemuAssignNextPCIAddress(&(vm->def->watchdog->info),
                                     vendor, product,
                                     addrs,  naddrs) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find PCI address for watchdog %s"),
                            virDomainWatchdogModelTypeToString(vm->def->watchdog->model));
            return -1;
        }
    }

    if (vm->def->memballoon &&
        qemuGetPCIMemballoonVendorProduct(vm->def->memballoon, &vendor, &product) == 0) {
        if (qemuAssignNextPCIAddress(&(vm->def->memballoon->info),
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
qemuInitPCIAddresses(struct qemud_driver *driver,
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

    ret = qemuDetectPCIAddresses(vm, addrs, naddrs);

    VIR_FREE(addrs);

    return ret;
}


static int qemudNextFreePort(struct qemud_driver *driver,
                             int startPort) {
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
qemuReturnPort(struct qemud_driver *driver,
                int port)
{
    if (port < QEMU_VNC_PORT_MIN)
        return;

    if (virBitmapClearBit(driver->reservedVNCPorts,
                          port - QEMU_VNC_PORT_MIN) < 0)
        VIR_DEBUG("Could not mark port %d as unused", port);
}


static int
qemuAssignPCIAddresses(virDomainDefPtr def)
{
    int ret = -1;
    unsigned long long qemuCmdFlags = 0;
    qemuDomainPCIAddressSetPtr addrs = NULL;

    if (qemuCapsExtractVersionInfo(def->emulator,
                                   NULL,
                                   &qemuCmdFlags) < 0)
        goto cleanup;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (!(addrs = qemuDomainPCIAddressSetCreate(def)))
            goto cleanup;

        if (qemuAssignDevicePCISlots(def, addrs) < 0)
            goto cleanup;
    }

    ret = 0;

cleanup:
    qemuDomainPCIAddressSetFree(addrs);

    return ret;
}


static int
qemuPrepareChardevDevice(virDomainDefPtr def ATTRIBUTE_UNUSED,
                         virDomainChrDefPtr dev,
                         void *opaque ATTRIBUTE_UNUSED)
{
    int fd;
    if (dev->type != VIR_DOMAIN_CHR_TYPE_FILE)
        return 0;

    if ((fd = open(dev->data.file.path, O_CREAT | O_APPEND, S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to pre-create chardev file '%s'"),
                             dev->data.file.path);
        return -1;
    }

    VIR_FORCE_CLOSE(fd);

    return 0;
}


struct qemudHookData {
    virConnectPtr conn;
    virDomainObjPtr vm;
    struct qemud_driver *driver;
};

static int qemudSecurityHook(void *data) {
    struct qemudHookData *h = data;

    /* This must take place before exec(), so that all QEMU
     * memory allocation is on the correct NUMA node
     */
    if (qemuAddToCgroup(h->driver, h->vm->def) < 0)
        return -1;

    /* This must be done after cgroup placement to avoid resetting CPU
     * affinity */
    if (qemudInitCpuAffinity(h->vm) < 0)
        return -1;

    if (h->driver->securityDriver &&
        h->driver->securityDriver->domainSetSecurityProcessLabel &&
        h->driver->securityDriver->domainSetSecurityProcessLabel(h->driver->securityDriver, h->vm) < 0)
        return -1;

    return 0;
}

static int
qemuPrepareMonitorChr(struct qemud_driver *driver,
                      virDomainChrDefPtr monConfig,
                      const char *vm)
{
    monConfig->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_MONITOR;

    monConfig->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monConfig->data.nix.listen = 1;

    if (!(monConfig->info.alias = strdup("monitor"))) {
        virReportOOMError();
        return -1;
    }

    if (virAsprintf(&monConfig->data.nix.path, "%s/%s.monitor",
                    driver->libDir, vm) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}

static int qemuDomainSnapshotSetCurrentActive(virDomainObjPtr vm,
                                              char *snapshotDir);
static int qemuDomainSnapshotSetCurrentInactive(virDomainObjPtr vm,
                                                char *snapshotDir);


#define START_POSTFIX ": starting up\n"
#define SHUTDOWN_POSTFIX ": shutting down\n"

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom,
                              bool start_paused,
                              int stdin_fd,
                              const char *stdin_path,
                              enum virVMOperationType vmop) {
    int ret;
    unsigned long long qemuCmdFlags;
    int pos = -1;
    char ebuf[1024];
    char *pidfile = NULL;
    int logfile = -1;
    char *timestamp;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCommandPtr cmd = NULL;

    struct qemudHookData hookData;
    hookData.conn = conn;
    hookData.vm = vm;
    hookData.driver = driver;

    DEBUG0("Beginning VM startup process");

    if (virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("VM is already active"));
        return -1;
    }

    /* Must be run before security labelling */
    DEBUG0("Preparing host devices");
    if (qemuPrepareHostDevices(driver, vm->def) < 0)
        goto cleanup;

    DEBUG0("Preparing chr devices");
    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuPrepareChardevDevice,
                               NULL) < 0)
        goto cleanup;

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    DEBUG0("Generating domain security label (if required)");
    if (driver->securityDriver &&
        driver->securityDriver->domainGenSecurityLabel) {
        ret = driver->securityDriver->domainGenSecurityLabel(driver->securityDriver,
                                                             vm);
        qemuDomainSecurityLabelAudit(vm, ret >= 0);
        if (ret < 0)
            goto cleanup;
    }

    DEBUG0("Generating setting domain security labels (if required)");
    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityAllLabel &&
        driver->securityDriver->domainSetSecurityAllLabel(driver->securityDriver,
                                                          vm, stdin_path) < 0) {
        goto cleanup;
    }

    /* Ensure no historical cgroup for this VM is lying around bogus
     * settings */
    DEBUG0("Ensuring no historical cgroup is lying around");
    qemuRemoveCgroup(driver, vm, 1);

    if (vm->def->ngraphics == 1) {
        if (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            vm->def->graphics[0]->data.vnc.autoport) {
            int port = qemudNextFreePort(driver, QEMU_VNC_PORT_MIN);
            if (port < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("Unable to find an unused VNC port"));
                goto cleanup;
            }
            vm->def->graphics[0]->data.vnc.port = port;
        } else if (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
                   vm->def->graphics[0]->data.spice.autoport) {
            int port = qemudNextFreePort(driver, QEMU_VNC_PORT_MIN);
            int tlsPort = -1;
            if (port < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("Unable to find an unused SPICE port"));
                goto cleanup;
            }

            if (driver->spiceTLS) {
                tlsPort = qemudNextFreePort(driver, port + 1);
                if (tlsPort < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("Unable to find an unused SPICE TLS port"));
                    qemuReturnPort(driver, port);
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

    DEBUG0("Creating domain log file");
    if ((logfile = qemudLogFD(driver, vm->def->name, false)) < 0)
        goto cleanup;

    DEBUG0("Determining emulator version");
    if (qemuCapsExtractVersionInfo(vm->def->emulator,
                                   NULL,
                                   &qemuCmdFlags) < 0)
        goto cleanup;

    DEBUG0("Setting up domain cgroup (if required)");
    if (qemuSetupCgroup(driver, vm) < 0)
        goto cleanup;

    if (VIR_ALLOC(priv->monConfig) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    DEBUG0("Preparing monitor state");
    if (qemuPrepareMonitorChr(driver, priv->monConfig, vm->def->name) < 0)
        goto cleanup;

#if HAVE_YAJL
    if (qemuCmdFlags & QEMUD_CMD_FLAG_MONITOR_JSON)
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
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        DEBUG0("Assigning domain PCI addresses");
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

    DEBUG0("Building emulator command line");
    vm->def->id = driver->nextvmid++;
    if (!(cmd = qemuBuildCommandLine(conn, driver, vm->def, priv->monConfig,
                                     priv->monJSON != 0, qemuCmdFlags,
                                     migrateFrom,
                                     vm->current_snapshot, vmop)))
        goto cleanup;

    if (qemuDomainSnapshotSetCurrentInactive(vm, driver->snapshotDir) < 0)
        goto cleanup;

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

    VIR_WARN("Executing %s", vm->def->emulator);
    virCommandSetPreExecHook(cmd, qemudSecurityHook, &hookData);

    if (stdin_fd != -1)
        virCommandSetInputFD(cmd, stdin_fd);

    virCommandSetOutputFD(cmd, &logfile);
    virCommandSetErrorFD(cmd, &logfile);
    virCommandNonblockingFDs(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    ret = virCommandRun(cmd, NULL);
    VIR_WARN("Executing done %s", vm->def->emulator);
    VIR_FREE(pidfile);

    /* wait for qemu process to to show up */
    if (ret == 0) {
        if (virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Domain %s didn't show up\n"), vm->def->name);
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

    DEBUG0("Waiting for monitor to show up");
    if (qemudWaitForMonitor(driver, vm, pos) < 0)
        goto cleanup;

    DEBUG0("Detecting VCPU PIDs");
    if (qemuDetectVcpuPIDs(driver, vm) < 0)
        goto cleanup;

    DEBUG0("Setting any required VM passwords");
    if (qemuInitPasswords(conn, driver, vm, qemuCmdFlags) < 0)
        goto cleanup;

    /* If we have -device, then addresses are assigned explicitly.
     * If not, then we have to detect dynamic ones here */
    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        DEBUG0("Determining domain device PCI addresses");
        if (qemuInitPCIAddresses(driver, vm) < 0)
            goto cleanup;
    }

    DEBUG0("Setting initial memory amount");
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorSetBalloon(priv->mon, vm->def->mem.cur_balloon) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cleanup;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (!start_paused) {
        DEBUG0("Starting domain CPUs");
        /* Allow the CPUS to start executing */
        if (doStartCPUs(driver, vm, conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("resume operation failed"));
            goto cleanup;
        }
    }


    DEBUG0("Writing domain status to disk");
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;

    /* Do this last, since it depends on domain being active */
    DEBUG0("Setting running domain def as transient");
    if (virDomainObjSetDefTransient(driver->caps, vm) < 0)
        goto cleanup;

    virCommandFree(cmd);
    VIR_FORCE_CLOSE(logfile);

    return 0;

cleanup:
    /* We jump here if we failed to start the VM for any reason, or
     * if we failed to initialize the now running VM. kill it off and
     * pretend we never started it */
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(logfile);
    qemudShutdownVMDaemon(driver, vm, 0);

    return -1;
}

static void qemudShutdownVMDaemon(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  int migrated) {
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

    if ((logfile = qemudLogFD(driver, vm->def->name, true)) < 0) {
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
        virDomainChrDefFree(priv->monConfig);
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
    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityAllLabel)
        driver->securityDriver->domainRestoreSecurityAllLabel(driver->securityDriver,
                                                              vm, migrated);
    if (driver->securityDriver &&
        driver->securityDriver->domainReleaseSecurityLabel)
        driver->securityDriver->domainReleaseSecurityLabel(driver->securityDriver,
                                                           vm);

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

    qemudRemoveDomainStatus(driver, vm);

    /* Remove VNC port from port reservation bitmap, but only if it was
       reserved by the driver (autoport=yes)
    */
    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport) {
        qemuReturnPort(driver, vm->def->graphics[0]->data.vnc.port);
    }
    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
        vm->def->graphics[0]->data.spice.autoport) {
        qemuReturnPort(driver, vm->def->graphics[0]->data.spice.port);
        qemuReturnPort(driver, vm->def->graphics[0]->data.spice.tlsPort);
    }

    vm->pid = -1;
    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;
    VIR_FREE(priv->vcpupids);
    priv->nvcpupids = 0;

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
            virReportOOMError();
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
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("qemu state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }

        if (conn->uri->path == NULL) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("no QEMU URI path given, try %s"),
                            qemu_driver->privileged
                            ? "qemu:///system"
                            : "qemu:///session");
                return VIR_DRV_OPEN_ERROR;
        }

        if (qemu_driver->privileged) {
            if (STRNEQ (conn->uri->path, "/system") &&
                STRNEQ (conn->uri->path, "/session")) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("unexpected QEMU URI path '%s', try qemu:///system"),
                                conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }
        } else {
            if (STRNEQ (conn->uri->path, "/session")) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
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


static int qemuIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}

static int qemuIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int kvmGetMaxVCPUs(void) {
    int maxvcpus = 1;

    int r, fd;

    fd = open(KVM_DEVICE, O_RDONLY);
    if (fd < 0) {
        virReportSystemError(errno, _("Unable to open %s"), KVM_DEVICE);
        return -1;
    }

    r = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS);
    if (r > 0)
        maxvcpus = r;

    VIR_FORCE_CLOSE(fd);
    return maxvcpus;
}


static int qemudGetMaxVCPUs(virConnectPtr conn ATTRIBUTE_UNUSED, const char *type) {
    if (!type)
        return 16;

    if (STRCASEEQ(type, "qemu"))
        return 16;

    if (STRCASEEQ(type, "kvm"))
        return kvmGetMaxVCPUs();

    if (STRCASEEQ(type, "kqemu"))
        return 1;

    qemuReportError(VIR_ERR_INVALID_ARG,
                    _("unknown type '%s'"), type);
    return -1;
}


static char *qemudGetCapabilities(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;
    virCapsPtr caps = NULL;
    char *xml = NULL;

    qemuDriverLock(driver);

    if ((caps = qemuCreateCapabilities(qemu_driver->caps,
                                       qemu_driver)) == NULL) {
        virCapabilitiesFree(caps);
        goto cleanup;
    }

    virCapabilitiesFree(qemu_driver->caps);
    qemu_driver->caps = caps;

    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError();

cleanup:
    qemuDriverUnlock(driver);

    return xml;
}


static int
qemudGetProcessInfo(unsigned long long *cpuTime, int *lastCpu, int pid,
                    int tid)
{
    char *proc;
    FILE *pidinfo;
    unsigned long long usertime, systime;
    int cpu;
    int ret;

    if (tid)
        ret = virAsprintf(&proc, "/proc/%d/task/%d/stat", pid, tid);
    else
        ret = virAsprintf(&proc, "/proc/%d/stat", pid);
    if (ret < 0)
        return -1;

    if (!(pidinfo = fopen(proc, "r"))) {
        /* VM probably shut down, so fake 0 */
        if (cpuTime)
            *cpuTime = 0;
        if (lastCpu)
            *lastCpu = 0;
        VIR_FREE(proc);
        return 0;
    }
    VIR_FREE(proc);

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
        VIR_FORCE_FCLOSE(pidinfo);
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

    VIR_FORCE_FCLOSE(pidinfo);

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
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


static int qemuDomainIsActive(virDomainPtr dom)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    qemuDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!obj) {
        qemuReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int qemuDomainIsPersistent(virDomainPtr dom)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    qemuDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!obj) {
        qemuReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int qemuDomainIsUpdated(virDomainPtr dom)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    qemuDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!obj) {
        qemuReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->updated;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int qemudGetVersion(virConnectPtr conn, unsigned long *version) {
    struct qemud_driver *driver = conn->privateData;
    int ret = -1;

    qemuDriverLock(driver);
    if (qemuCapsExtractVersion(driver->caps, &driver->qemuVersion) < 0)
        goto cleanup;

    *version = driver->qemuVersion;
    ret = 0;

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

static int qemudListDomains(virConnectPtr conn, int *ids, int nids) {
    struct qemud_driver *driver = conn->privateData;
    int n;

    qemuDriverLock(driver);
    n = virDomainObjListGetActiveIDs(&driver->domains, ids, nids);
    qemuDriverUnlock(driver);

    return n;
}

static int qemudNumDomains(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;
    int n;

    qemuDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 1);
    qemuDriverUnlock(driver);

    return n;
}

static virDomainPtr qemudDomainCreate(virConnectPtr conn, const char *xml,
                                      unsigned int flags) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;

    virCheckFlags(VIR_DOMAIN_START_PAUSED, NULL);

    qemuDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virSecurityDriverVerify(def) < 0)
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (qemudCanonicalizeMachine(driver, def) < 0)
        goto cleanup;

    if (qemuAssignPCIAddresses(def) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, false)))
        goto cleanup;

    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup; /* XXXX free the 'vm' we created ? */

    if (qemudStartVMDaemon(conn, driver, vm, NULL,
                           (flags & VIR_DOMAIN_START_PAUSED) != 0,
                           -1, NULL, VIR_VM_OP_CREATE) < 0) {
        qemuDomainStartAudit(vm, "booted", false);
        if (qemuDomainObjEndJob(vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    qemuDomainStartAudit(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
    qemuDomainObjPrivatePtr priv;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (priv->jobActive == QEMU_JOB_MIGRATION_OUT) {
        if (vm->state != VIR_DOMAIN_PAUSED) {
            VIR_DEBUG("Requesting domain pause on %s",
                      vm->def->name);
            priv->jobSignals |= QEMU_JOB_SIGNAL_SUSPEND;
        }
        ret = 0;
        goto cleanup;
    } else {
        if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
            goto cleanup;

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto endjob;
        }
        if (vm->state != VIR_DOMAIN_PAUSED) {
            if (doStopCPUs(driver, vm) < 0) {
                goto endjob;
            }
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_SUSPENDED,
                                             VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
        }
        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
            goto endjob;
        ret = 0;
    }

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }
    if (vm->state == VIR_DOMAIN_PAUSED) {
        if (doStartCPUs(driver, vm, dom->conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("resume operation failed"));
            goto endjob;
        }
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto endjob;
    ret = 0;

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainObjEnterMonitor(vm);
    ret = qemuMonitorSystemPowerdown(priv->mon);
    qemuDomainObjExitMonitor(vm);

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    qemudShutdownVMDaemon(driver, vm, 0);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    qemuDomainStopAudit(vm, "destroyed");

    if (!vm->persistent) {
        if (qemuDomainObjEndJob(vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
    }
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!(type = strdup(vm->def->os.type)))
        virReportOOMError();

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = vm->def->mem.max_balloon;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    struct qemud_driver *driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1, r;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (newmem > vm->def->mem.max_balloon) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("cannot set memory higher than max memory"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;
    qemuDomainObjEnterMonitor(vm);
    r = qemuMonitorSetBalloon(priv->mon, newmem);
    qemuDomainObjExitMonitor(vm);
    if (r < 0)
        goto endjob;

    /* Lack of balloon support is a fatal error */
    if (r == 0) {
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        "%s", _("cannot set memory of an active domain"));
        goto endjob;
    }

    ret = 0;
endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    info->state = vm->state;

    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (qemudGetProcessInfo(&(info->cpuTime), NULL, vm->pid, 0) < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, ("cannot read cputime for domain"));
            goto cleanup;
        }
    }

    info->maxMem = vm->def->mem.max_balloon;

    if (virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;

        if ((vm->def->memballoon != NULL) &&
            (vm->def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_NONE)) {
            info->memory = vm->def->mem.max_balloon;
        } else if (!priv->jobActive) {
            if (qemuDomainObjBeginJob(vm) < 0)
                goto cleanup;
            if (!virDomainObjIsActive(vm))
                err = 0;
            else {
                qemuDomainObjEnterMonitor(vm);
                err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
                qemuDomainObjExitMonitor(vm);
            }
            if (qemuDomainObjEndJob(vm) == 0) {
                vm = NULL;
                goto cleanup;
            }

            if (err < 0)
                goto cleanup;
            if (err == 0)
                /* Balloon not supported, so maxmem is always the allocation */
                info->memory = vm->def->mem.max_balloon;
            else
                info->memory = balloon;
        } else {
            info->memory = vm->def->mem.cur_balloon;
        }
    } else {
        info->memory = vm->def->mem.cur_balloon;
    }

    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


/** qemuDomainMigrateOffline:
 * Pause domain for non-live migration.
 */
static int
qemuDomainMigrateOffline(struct qemud_driver *driver,
                         virDomainObjPtr vm)
{
    int ret;

    ret = doStopCPUs(driver, vm);
    if (ret == 0) {
        virDomainEventPtr event;

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
        if (event)
            qemuDomainEventQueue(driver, event);
    }

    return ret;
}


static int
qemuDomainWaitForMigrationComplete(struct qemud_driver *driver, virDomainObjPtr vm)
{
    int ret = -1;
    int status;
    unsigned long long memProcessed;
    unsigned long long memRemaining;
    unsigned long long memTotal;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    while (priv->jobInfo.type == VIR_DOMAIN_JOB_UNBOUNDED) {
        /* Poll every 50ms for progress & to allow cancellation */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000ull };
        struct timeval now;
        int rc;
        const char *job;

        switch (priv->jobActive) {
            case QEMU_JOB_MIGRATION_OUT:
                job = _("migration job");
                break;
            case QEMU_JOB_SAVE:
                job = _("domain save job");
                break;
            case QEMU_JOB_DUMP:
                job = _("domain core dump job");
                break;
            default:
                job = _("job");
        }


        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s: %s",
                            job, _("guest unexpectedly quit"));
            goto cleanup;
        }

        if (priv->jobSignals & QEMU_JOB_SIGNAL_CANCEL) {
            priv->jobSignals ^= QEMU_JOB_SIGNAL_CANCEL;
            VIR_DEBUG0("Cancelling job at client request");
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            rc = qemuMonitorMigrateCancel(priv->mon);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (rc < 0) {
                VIR_WARN0("Unable to cancel job");
            }
        } else if (priv->jobSignals & QEMU_JOB_SIGNAL_SUSPEND) {
            priv->jobSignals ^= QEMU_JOB_SIGNAL_SUSPEND;
            VIR_DEBUG0("Pausing domain for non-live migration");
            if (qemuDomainMigrateOffline(driver, vm) < 0)
                VIR_WARN0("Unable to pause domain");
        } else if (priv->jobSignals & QEMU_JOB_SIGNAL_MIGRATE_DOWNTIME) {
            unsigned long long ms = priv->jobSignalsData.migrateDowntime;

            priv->jobSignals ^= QEMU_JOB_SIGNAL_MIGRATE_DOWNTIME;
            priv->jobSignalsData.migrateDowntime = 0;
            VIR_DEBUG("Setting migration downtime to %llums", ms);
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            rc = qemuMonitorSetMigrationDowntime(priv->mon, ms);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (rc < 0)
                VIR_WARN0("Unable to set migration downtime");
        }

        /* Repeat check because the job signals might have caused
         * guest to die
         */
        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s: %s",
                            job, _("guest unexpectedly quit"));
            goto cleanup;
        }

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        rc = qemuMonitorGetMigrationStatus(priv->mon,
                                           &status,
                                           &memProcessed,
                                           &memRemaining,
                                           &memTotal);
        qemuDomainObjExitMonitorWithDriver(driver, vm);

        if (rc < 0) {
            priv->jobInfo.type = VIR_DOMAIN_JOB_FAILED;
            goto cleanup;
        }

        if (gettimeofday(&now, NULL) < 0) {
            priv->jobInfo.type = VIR_DOMAIN_JOB_FAILED;
            virReportSystemError(errno, "%s",
                                 _("cannot get time of day"));
            goto cleanup;
        }
        priv->jobInfo.timeElapsed = timeval_to_ms(now) - priv->jobStart;

        switch (status) {
        case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
            priv->jobInfo.type = VIR_DOMAIN_JOB_NONE;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s: %s", job, _("is not active"));
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
            priv->jobInfo.dataTotal = memTotal;
            priv->jobInfo.dataRemaining = memRemaining;
            priv->jobInfo.dataProcessed = memProcessed;

            priv->jobInfo.memTotal = memTotal;
            priv->jobInfo.memRemaining = memRemaining;
            priv->jobInfo.memProcessed = memProcessed;
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
            priv->jobInfo.type = VIR_DOMAIN_JOB_COMPLETED;
            ret = 0;
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
            priv->jobInfo.type = VIR_DOMAIN_JOB_FAILED;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s: %s", job, _("unexpectedly failed"));
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
            priv->jobInfo.type = VIR_DOMAIN_JOB_CANCELLED;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s: %s", job, _("canceled by client"));
            break;
        }

        virDomainObjUnlock(vm);
        qemuDriverUnlock(driver);

        nanosleep(&ts, NULL);

        qemuDriverLock(driver);
        virDomainObjLock(vm);
    }

cleanup:
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

struct fileOpHookData {
    virDomainPtr dom;
    const char *path;
    char *xml;
    struct qemud_save_header *header;
};

/* return -errno on failure, or 0 on success */
static int qemudDomainSaveFileOpHook(int fd, void *data) {
    struct fileOpHookData *hdata = data;
    int ret = 0;

    if (safewrite(fd, hdata->header, sizeof(*hdata->header)) != sizeof(*hdata->header)) {
        ret = -errno;
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("failed to write header to domain save file '%s'"),
                        hdata->path);
        goto endjob;
    }

    if (safewrite(fd, hdata->xml, hdata->header->xml_len) != hdata->header->xml_len) {
        ret = -errno;
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                         _("failed to write xml to '%s'"), hdata->path);
        goto endjob;
    }
endjob:
    return ret;
}

/* this internal function expects the driver lock to already be held on entry */
static int qemudDomainSaveFlag(struct qemud_driver *driver, virDomainPtr dom,
                               virDomainObjPtr vm, const char *path,
                               int compressed)
{
    char *xml = NULL;
    struct qemud_save_header header;
    struct fileOpHookData hdata;
    int bypassSecurityDriver = 0;
    int ret = -1;
    int rc;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;
    struct stat sb;
    int is_reg = 0;
    unsigned long long offset;
    virCgroupPtr cgroup = NULL;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic));
    header.version = QEMUD_SAVE_VERSION;

    header.compressed = compressed;

    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    priv->jobActive = QEMU_JOB_SAVE;

    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    /* Pause */
    if (vm->state == VIR_DOMAIN_RUNNING) {
        header.was_running = 1;
        if (doStopCPUs(driver, vm) < 0)
            goto endjob;

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto endjob;
        }
    }

    /* Get XML for the domain */
    xml = virDomainDefFormat(vm->def, VIR_DOMAIN_XML_SECURE);
    if (!xml) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to get domain xml"));
        goto endjob;
    }
    header.xml_len = strlen(xml) + 1;

    /* path might be a pre-existing block dev, in which case
     * we need to skip the create step, and also avoid unlink
     * in the failure case */
    if (stat(path, &sb) < 0) {
        /* Avoid throwing an error here, since it is possible
         * that with NFS we can't actually stat() the file.
         * The subsequent codepaths will still raise an error
         * if a truely fatal problem is hit */
        is_reg = 1;
    } else {
        is_reg = S_ISREG(sb.st_mode);
    }

    offset = sizeof(header) + header.xml_len;

    /* Due to way we append QEMU state on our header with dd,
     * we need to ensure there's a 512 byte boundary. Unfortunately
     * we don't have an explicit offset in the header, so we fake
     * it by padding the XML string with NULLs.
     */
    if (offset % QEMU_MONITOR_MIGRATE_TO_FILE_BS) {
        unsigned long long pad =
            QEMU_MONITOR_MIGRATE_TO_FILE_BS -
            (offset % QEMU_MONITOR_MIGRATE_TO_FILE_BS);

        if (VIR_REALLOC_N(xml, header.xml_len + pad) < 0) {
            virReportOOMError();
            goto endjob;
        }
        memset(xml + header.xml_len, 0, pad);
        offset += pad;
        header.xml_len += pad;
    }

    /* Setup hook data needed by virFileOperation hook function */
    hdata.dom = dom;
    hdata.path = path;
    hdata.xml = xml;
    hdata.header = &header;

    /* Write header to file, followed by XML */

    /* First try creating the file as root */
    if (!is_reg) {
        int fd = open(path, O_WRONLY | O_TRUNC);
        if (fd < 0) {
            virReportSystemError(errno, _("unable to open %s"), path);
            goto endjob;
        }
        if (qemudDomainSaveFileOpHook(fd, &hdata) < 0) {
            VIR_FORCE_CLOSE(fd);
            goto endjob;
        }
        if (VIR_CLOSE(fd) < 0) {
            virReportSystemError(errno, _("unable to close %s"), path);
            goto endjob;
        }
    } else {
        if ((rc = virFileOperation(path, O_CREAT|O_TRUNC|O_WRONLY,
                                  S_IRUSR|S_IWUSR,
                                  getuid(), getgid(),
                                  qemudDomainSaveFileOpHook, &hdata,
                                  0)) < 0) {
            /* If we failed as root, and the error was permission-denied
               (EACCES or EPERM), assume it's on a network-connected share
               where root access is restricted (eg, root-squashed NFS). If the
               qemu user (driver->user) is non-root, just set a flag to
               bypass security driver shenanigans, and retry the operation
               after doing setuid to qemu user */

            if (((rc != -EACCES) && (rc != -EPERM)) ||
                driver->user == getuid()) {
                virReportSystemError(-rc, _("Failed to create domain save file '%s'"),
                                     path);
                goto endjob;
            }

            /* On Linux we can also verify the FS-type of the directory. */
            switch (virStorageFileIsSharedFS(path)) {
                case 1:
                   /* it was on a network share, so we'll continue
                    * as outlined above
                    */
                   break;

                case -1:
                   virReportSystemError(errno,
                                        _("Failed to create domain save file "
                                          "'%s': couldn't determine fs type"),
                                        path);
                   goto endjob;
                   break;

                case 0:
                default:
                   /* local file - log the error returned by virFileOperation */
                   virReportSystemError(-rc,
                                        _("Failed to create domain save file '%s'"),
                                        path);
                   goto endjob;
                   break;

            }

            /* Retry creating the file as driver->user */

            if ((rc = virFileOperation(path, O_CREAT|O_TRUNC|O_WRONLY,
                                       S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP,
                                       driver->user, driver->group,
                                       qemudDomainSaveFileOpHook, &hdata,
                                       VIR_FILE_OP_AS_UID)) < 0) {
                virReportSystemError(-rc, _("Error from child process creating '%s'"),
                                 path);
                goto endjob;
            }

            /* Since we had to setuid to create the file, and the fstype
               is NFS, we assume it's a root-squashing NFS share, and that
               the security driver stuff would have failed anyway */

            bypassSecurityDriver = 1;
        }
    }


    if (!is_reg &&
        qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unable to find cgroup for %s\n"),
                            vm->def->name);
            goto endjob;
        }
        rc = virCgroupAllowDevicePath(cgroup, path);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to allow device %s for %s"),
                                 path, vm->def->name);
            goto endjob;
        }
    }

    if ((!bypassSecurityDriver) &&
        driver->securityDriver &&
        driver->securityDriver->domainSetSavedStateLabel &&
        driver->securityDriver->domainSetSavedStateLabel(driver->securityDriver,
                                                         vm, path) == -1)
        goto endjob;

    if (header.compressed == QEMUD_SAVE_FORMAT_RAW) {
        const char *args[] = { "cat", NULL };
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        rc = qemuMonitorMigrateToFile(priv->mon,
                                      QEMU_MONITOR_MIGRATE_BACKGROUND,
                                      args, path, offset);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    } else {
        const char *prog = qemudSaveCompressionTypeToString(header.compressed);
        const char *args[] = {
            prog,
            "-c",
            NULL
        };
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        rc = qemuMonitorMigrateToFile(priv->mon,
                                      QEMU_MONITOR_MIGRATE_BACKGROUND,
                                      args, path, offset);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

    if (rc < 0)
        goto endjob;

    rc = qemuDomainWaitForMigrationComplete(driver, vm);

    if (rc < 0)
        goto endjob;

    if ((!bypassSecurityDriver) &&
        driver->securityDriver &&
        driver->securityDriver->domainRestoreSavedStateLabel &&
        driver->securityDriver->domainRestoreSavedStateLabel(driver->securityDriver,
                                                             vm, path) == -1)
        VIR_WARN("failed to restore save state label on %s", path);

    if (cgroup != NULL) {
        rc = virCgroupDenyDevicePath(cgroup, path);
        if (rc != 0)
            VIR_WARN("Unable to deny device %s for %s %d",
                     path, vm->def->name, rc);
    }

    ret = 0;

    /* Shut it down */
    qemudShutdownVMDaemon(driver, vm, 0);
    qemuDomainStopAudit(vm, "saved");
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SAVED);
    if (!vm->persistent) {
        if (qemuDomainObjEndJob(vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
    }

endjob:
    if (vm) {
        if (ret != 0) {
            if (header.was_running && virDomainObjIsActive(vm)) {
                rc = doStartCPUs(driver, vm, dom->conn);
                if (rc < 0)
                    VIR_WARN0("Unable to resume guest CPUs after save failure");
            }

            if (cgroup != NULL) {
                rc = virCgroupDenyDevicePath(cgroup, path);
                if (rc != 0)
                    VIR_WARN("Unable to deny device %s for %s: %d",
                             path, vm->def->name, rc);
            }

            if ((!bypassSecurityDriver) &&
                driver->securityDriver &&
                driver->securityDriver->domainRestoreSavedStateLabel &&
                driver->securityDriver->domainRestoreSavedStateLabel(driver->securityDriver,
                                                                     vm, path) == -1)
                VIR_WARN("failed to restore save state label on %s", path);
        }

        if (qemuDomainObjEndJob(vm) == 0)
            vm = NULL;
    }

cleanup:
    VIR_FREE(xml);
    if (ret != 0 && is_reg)
        unlink(path);
    if (event)
        qemuDomainEventQueue(driver, event);
    virCgroupFree(&cgroup);
    return ret;
}

/* Returns true if a compression program is available in PATH */
static bool qemudCompressProgramAvailable(enum qemud_save_formats compress)
{
    const char *prog;
    char *c;

    if (compress == QEMUD_SAVE_FORMAT_RAW)
        return true;
    prog = qemudSaveCompressionTypeToString(compress);
    c = virFindFileInPath(prog);
    if (!c)
        return false;
    VIR_FREE(c);
    return true;
}

static int qemudDomainSave(virDomainPtr dom, const char *path)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int compressed;
    int ret = -1;
    virDomainObjPtr vm = NULL;

    qemuDriverLock(driver);

    if (driver->saveImageFormat == NULL)
        compressed = QEMUD_SAVE_FORMAT_RAW;
    else {
        compressed = qemudSaveCompressionTypeFromString(driver->saveImageFormat);
        if (compressed < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Invalid save image format specified "
                                    "in configuration file"));
            return -1;
        }
        if (!qemudCompressProgramAvailable(compressed)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Compression program for image format "
                                    "in configuration file isn't available"));
            return -1;
        }
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = qemudDomainSaveFlag(driver, dom, vm, path, compressed);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);

    return ret;
}

static char *
qemuDomainManagedSavePath(struct qemud_driver *driver, virDomainObjPtr vm) {
    char *ret;

    if (virAsprintf(&ret, "%s/%s.save", driver->saveDir, vm->def->name) < 0) {
        virReportOOMError();
        return(NULL);
    }

    return(ret);
}

static int
qemuDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    char *name = NULL;
    int ret = -1;
    int compressed;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    name = qemuDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    VIR_DEBUG("Saving state to %s", name);

    compressed = QEMUD_SAVE_FORMAT_RAW;
    ret = qemudDomainSaveFlag(driver, dom, vm, name, compressed);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    VIR_FREE(name);

    return ret;
}

static int
qemuDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    char *name = NULL;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    name = qemuDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    ret = virFileExists(name);

cleanup:
    VIR_FREE(name);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemuDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    char *name = NULL;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    name = qemuDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    ret = unlink(name);

cleanup:
    VIR_FREE(name);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int doCoreDump(struct qemud_driver *driver,
                      virDomainObjPtr vm,
                      const char *path,
                      enum qemud_save_formats compress)
{
    int fd = -1;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    priv = vm->privateData;

    /* Create an empty file with appropriate ownership.  */
    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("failed to create '%s'"), path);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("unable to save file %s"),
                             path);
        goto cleanup;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSavedStateLabel &&
        driver->securityDriver->domainSetSavedStateLabel(driver->securityDriver,
                                                         vm, path) == -1)
        goto cleanup;

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (compress == QEMUD_SAVE_FORMAT_RAW) {
        const char *args[] = {
            "cat",
            NULL,
        };
        ret = qemuMonitorMigrateToFile(priv->mon,
                                       QEMU_MONITOR_MIGRATE_BACKGROUND,
                                       args, path, 0);
    } else {
        const char *prog = qemudSaveCompressionTypeToString(compress);
        const char *args[] = {
            prog,
            "-c",
            NULL,
        };
        ret = qemuMonitorMigrateToFile(priv->mon,
                                       QEMU_MONITOR_MIGRATE_BACKGROUND,
                                       args, path, 0);
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (ret < 0)
        goto cleanup;

    ret = qemuDomainWaitForMigrationComplete(driver, vm);

    if (ret < 0)
        goto cleanup;

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSavedStateLabel &&
        driver->securityDriver->domainRestoreSavedStateLabel(driver->securityDriver,
                                                             vm, path) == -1)
        goto cleanup;

cleanup:
    if (ret != 0)
        unlink(path);
    return ret;
}

static enum qemud_save_formats
getCompressionType(struct qemud_driver *driver)
{
    int compress = QEMUD_SAVE_FORMAT_RAW;

    /*
     * We reuse "save" flag for "dump" here. Then, we can support the same
     * format in "save" and "dump".
     */
    if (driver->dumpImageFormat) {
        compress = qemudSaveCompressionTypeFromString(driver->dumpImageFormat);
        if (compress < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("Invalid dump image format specified in "
                              "configuration file, using raw"));
            return QEMUD_SAVE_FORMAT_RAW;
        }
        if (!qemudCompressProgramAvailable(compress)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Compression program for dump image format "
                                    "in configuration file isn't available, "
                                    "using raw"));
            return QEMUD_SAVE_FORMAT_RAW;
        }
    }
    return compress;
}

static int qemudDomainCoreDump(virDomainPtr dom,
                               const char *path,
                               int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int resume = 0, paused = 0;
    int ret = -1;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    priv->jobActive = QEMU_JOB_DUMP;

    /* Migrate will always stop the VM, so the resume condition is
       independent of whether the stop command is issued.  */
    resume = (vm->state == VIR_DOMAIN_RUNNING);

    /* Pause domain for non-live dump */
    if (!(flags & VIR_DUMP_LIVE) && vm->state == VIR_DOMAIN_RUNNING) {
        if (doStopCPUs(driver, vm) < 0)
            goto endjob;
        paused = 1;

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto endjob;
        }
    }

    ret = doCoreDump(driver, vm, path, getCompressionType(driver));
    if (ret < 0)
        goto endjob;

    paused = 1;

endjob:
    if ((ret == 0) && (flags & VIR_DUMP_CRASH)) {
        qemudShutdownVMDaemon(driver, vm, 0);
        qemuDomainStopAudit(vm, "crashed");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    }

    /* Since the monitor is always attached to a pty for libvirt, it
       will support synchronous operations so we always get here after
       the migration is complete.  */
    else if (resume && paused && virDomainObjIsActive(vm)) {
        if (doStartCPUs(driver, vm, dom->conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("resuming after dump failed"));
        }
    }

    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;
    else if ((ret == 0) && (flags & VIR_DUMP_CRASH) && !vm->persistent) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

static void processWatchdogEvent(void *data, void *opaque)
{
    int ret;
    struct watchdogEvent *wdEvent = data;
    struct qemud_driver *driver = opaque;

    switch (wdEvent->action) {
    case VIR_DOMAIN_WATCHDOG_ACTION_DUMP:
        {
            char *dumpfile;
            int i;

            i = virAsprintf(&dumpfile, "%s/%s-%u",
                            driver->autoDumpPath,
                            wdEvent->vm->def->name,
                            (unsigned int)time(NULL));

            qemuDriverLock(driver);
            virDomainObjLock(wdEvent->vm);

            if (qemuDomainObjBeginJobWithDriver(driver, wdEvent->vm) < 0)
                break;

            if (!virDomainObjIsActive(wdEvent->vm)) {
                qemuReportError(VIR_ERR_OPERATION_INVALID,
                                "%s", _("domain is not running"));
                break;
            }

            ret = doCoreDump(driver,
                             wdEvent->vm,
                             dumpfile,
                             getCompressionType(driver));
            if (ret < 0)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("Dump failed"));

            ret = doStartCPUs(driver, wdEvent->vm, NULL);

            if (ret < 0)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("Resuming after dump failed"));

            if (qemuDomainObjEndJob(wdEvent->vm) > 0)
                virDomainObjUnlock(wdEvent->vm);

            qemuDriverUnlock(driver);

            VIR_FREE(dumpfile);
        }
        break;
    }

    VIR_FREE(wdEvent);
}

static int qemudDomainHotplugVcpus(virDomainObjPtr vm, unsigned int nvcpus)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, rc;
    int ret = -1;

    qemuDomainObjEnterMonitor(vm);

    /* We need different branches here, because we want to offline
     * in reverse order to onlining, so any partial fail leaves us in a
     * reasonably sensible state */
    if (nvcpus > vm->def->vcpus) {
        for (i = vm->def->vcpus ; i < nvcpus ; i++) {
            /* Online new CPU */
            rc = qemuMonitorSetCPU(priv->mon, i, 1);
            if (rc == 0)
                goto unsupported;
            if (rc < 0)
                goto cleanup;

            vm->def->vcpus++;
        }
    } else {
        for (i = vm->def->vcpus - 1 ; i >= nvcpus ; i--) {
            /* Offline old CPU */
            rc = qemuMonitorSetCPU(priv->mon, i, 0);
            if (rc == 0)
                goto unsupported;
            if (rc < 0)
                goto cleanup;

            vm->def->vcpus--;
        }
    }

    ret = 0;

cleanup:
    qemuDomainObjExitMonitor(vm);
    return ret;

unsupported:
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot change vcpu count of this domain"));
    goto cleanup;
}


static int
qemudDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef;
    const char * type;
    int max;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    /* At least one of LIVE or CONFIG must be set.  MAXIMUM cannot be
     * mixed with LIVE.  */
    if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) == 0 ||
        (flags & (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) ==
         (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }
    if (!nvcpus || (unsigned short) nvcpus != nvcpus) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("argument out of range: %d"), nvcpus);
        return -1;
    }

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) && (flags & VIR_DOMAIN_VCPU_LIVE)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto endjob;
    }

    if (!vm->persistent && (flags & VIR_DOMAIN_VCPU_CONFIG)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot change persistent config of a transient domain"));
        goto endjob;
    }

    if (!(type = virDomainVirtTypeToString(vm->def->virtType))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unknown virt type in domain definition '%d'"),
                        vm->def->virtType);
        goto endjob;
    }

    if ((max = qemudGetMaxVCPUs(NULL, type)) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("could not determine max vcpus for the domain"));
        goto endjob;
    }

    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM) && vm->def->maxvcpus < max) {
        max = vm->def->maxvcpus;
    }

    if (nvcpus > max) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("requested vcpus is greater than max allowable"
                          " vcpus for the domain: %d > %d"), nvcpus, max);
        goto endjob;
    }

    if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
        goto endjob;

    switch (flags) {
    case VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_CONFIG:
        persistentDef->maxvcpus = nvcpus;
        if (nvcpus < persistentDef->vcpus)
            persistentDef->vcpus = nvcpus;
        ret = 0;
        break;

    case VIR_DOMAIN_VCPU_CONFIG:
        persistentDef->vcpus = nvcpus;
        ret = 0;
        break;

    case VIR_DOMAIN_VCPU_LIVE:
        ret = qemudDomainHotplugVcpus(vm, nvcpus);
        break;

    case VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG:
        ret = qemudDomainHotplugVcpus(vm, nvcpus);
        if (ret == 0) {
            persistentDef->vcpus = nvcpus;
        }
        break;
    }

    /* Save the persistent config to disk */
    if (flags & VIR_DOMAIN_VCPU_CONFIG)
        ret = virDomainSaveConfig(driver->configDir, persistentDef);

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
qemudDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return qemudDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_VCPU_LIVE);
}


static int
qemudDomainPinVcpu(virDomainPtr dom,
                   unsigned int vcpu,
                   unsigned char *cpumap,
                   int maplen) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int maxcpu, hostcpus;
    virNodeInfo nodeinfo;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s",_("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (vcpu > (priv->nvcpupids-1)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("vcpu number out of range %d > %d"),
                        vcpu, priv->nvcpupids);
        goto cleanup;
    }

    if (nodeGetInfo(dom->conn, &nodeinfo) < 0)
        goto cleanup;

    hostcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    if (priv->vcpupids != NULL) {
        if (virProcessInfoSetAffinity(priv->vcpupids[vcpu],
                                      cpumap, maplen, maxcpu) < 0)
            goto cleanup;
    } else {
        qemuReportError(VIR_ERR_NO_SUPPORT,
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
    int i, v, maxcpu, hostcpus;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s",
                        _("cannot list vcpu pinning for an inactive domain"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (nodeGetInfo(dom->conn, &nodeinfo) < 0)
        goto cleanup;

    hostcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    /* Clamp to actual number of vcpus */
    if (maxinfo > priv->nvcpupids)
        maxinfo = priv->nvcpupids;

    if (maxinfo >= 1) {
        if (info != NULL) {
            memset(info, 0, sizeof(*info) * maxinfo);
            for (i = 0 ; i < maxinfo ; i++) {
                info[i].number = i;
                info[i].state = VIR_VCPU_RUNNING;

                if (priv->vcpupids != NULL &&
                    qemudGetProcessInfo(&(info[i].cpuTime),
                                        &(info[i].cpu),
                                        vm->pid,
                                        priv->vcpupids[i]) < 0) {
                    virReportSystemError(errno, "%s",
                                         _("cannot get vCPU placement & pCPU time"));
                    goto cleanup;
                }
            }
        }

        if (cpumaps != NULL) {
            memset(cpumaps, 0, maplen * maxinfo);
            if (priv->vcpupids != NULL) {
                for (v = 0 ; v < maxinfo ; v++) {
                    unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, v);

                    if (virProcessInfoGetAffinity(priv->vcpupids[v],
                                                  cpumap, maplen, maxcpu) < 0)
                        goto cleanup;
                }
            } else {
                qemuReportError(VIR_ERR_NO_SUPPORT,
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


static int
qemudDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    /* Exactly one of LIVE or CONFIG must be set.  */
    if (!(flags & VIR_DOMAIN_VCPU_LIVE) == !(flags & VIR_DOMAIN_VCPU_CONFIG)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_VCPU_LIVE) {
        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("domain not active"));
            goto cleanup;
        }
        def = vm->def;
    } else {
        def = vm->newDef ? vm->newDef : vm->def;
    }

    ret = (flags & VIR_DOMAIN_VCPU_MAXIMUM) ? def->maxvcpus : def->vcpus;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
qemudDomainGetMaxVcpus(virDomainPtr dom)
{
    return qemudDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_LIVE |
                                          VIR_DOMAIN_VCPU_MAXIMUM));
}

static int qemudDomainGetSecurityLabel(virDomainPtr dom, virSecurityLabelPtr seclabel)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    memset(seclabel, 0, sizeof(*seclabel));

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainVirtTypeToString(vm->def->virtType)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
    if (virDomainObjIsActive(vm)) {
        if (driver->securityDriver &&
            driver->securityDriver->domainGetSecurityProcessLabel &&
            driver->securityDriver->domainGetSecurityProcessLabel(driver->securityDriver,
                                                                  vm, seclabel) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("Failed to get security label"));
            goto cleanup;
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
    if (!driver->securityPrimaryDriver) {
        memset(secmodel, 0, sizeof (*secmodel));
        goto cleanup;
    }

    p = driver->caps->host.secModel.model;
    if (strlen(p) >= VIR_SECURITY_MODEL_BUFLEN-1) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("security model string exceeds max %d bytes"),
                        VIR_SECURITY_MODEL_BUFLEN-1);
        ret = -1;
        goto cleanup;
    }
    strcpy(secmodel->model, p);

    p = driver->caps->host.secModel.doi;
    if (strlen(p) >= VIR_SECURITY_DOI_BUFLEN-1) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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

/* qemudOpenAsUID() - pipe/fork/setuid/open a file, and return the
   pipe fd to caller, so that it can read from the file. Also return
   the pid of the child process, so the caller can wait for it to exit
   after it's finished reading (to avoid a zombie, if nothing
   else). */

static int
qemudOpenAsUID(const char *path, uid_t uid, gid_t gid, pid_t *child_pid)
{
    int pipefd[2];
    int fd = -1;

    *child_pid = -1;

    if (pipe(pipefd) < 0) {
        virReportSystemError(errno,
                             _("failed to create pipe to read '%s'"),
                             path);
        pipefd[0] = pipefd[1] = -1;
        goto parent_cleanup;
    }

    int forkRet = virFork(child_pid);

    if (*child_pid < 0) {
        virReportSystemError(errno,
                             _("failed to fork child to read '%s'"),
                             path);
        goto parent_cleanup;
    }

    if (*child_pid > 0) {

        /* parent */

        /* parent doesn't need the write side of the pipe */
        VIR_FORCE_CLOSE(pipefd[1]);

        if (forkRet < 0) {
            virReportSystemError(errno,
                                 _("failed in parent after forking child to read '%s'"),
                                 path);
            goto parent_cleanup;
        }
        /* caller gets the read side of the pipe */
        fd = pipefd[0];
        pipefd[0] = -1;
parent_cleanup:
        VIR_FORCE_CLOSE(pipefd[0]);
        VIR_FORCE_CLOSE(pipefd[1]);
        if ((fd < 0) && (*child_pid > 0)) {
            /* a child process was started and subsequently an error
               occurred in the parent, so we need to wait for it to
               exit, but its status is inconsequential. */
            while ((waitpid(*child_pid, NULL, 0) == -1)
                   && (errno == EINTR)) {
                /* empty */
            }
            *child_pid = -1;
        }
        return fd;
    }

    /* child */

    /* setuid to the qemu user, then open the file, read it,
       and stuff it into the pipe for the parent process to
       read */
    int exit_code;
    char *buf = NULL;
    size_t bufsize = 1024 * 1024;
    int bytesread;

    /* child doesn't need the read side of the pipe */
    VIR_FORCE_CLOSE(pipefd[0]);

    if (forkRet < 0) {
        exit_code = errno;
        virReportSystemError(errno,
                             _("failed in child after forking to read '%s'"),
                             path);
        goto child_cleanup;
    }

    if (virSetUIDGID(uid, gid) < 0) {
       exit_code = errno;
       goto child_cleanup;
    }

    if ((fd = open(path, O_RDONLY)) < 0) {
        exit_code = errno;
        virReportSystemError(errno,
                             _("cannot open '%s' as uid %d"),
                             path, uid);
        goto child_cleanup;
    }

    if (VIR_ALLOC_N(buf, bufsize) < 0) {
        exit_code = ENOMEM;
        virReportOOMError();
        goto child_cleanup;
    }

    /* read from fd and write to pipefd[1] until EOF */
    do {
        if ((bytesread = saferead(fd, buf, bufsize)) < 0) {
            exit_code = errno;
            virReportSystemError(errno,
                                 _("child failed reading from '%s'"),
                                 path);
            goto child_cleanup;
        }
        if (safewrite(pipefd[1], buf, bytesread) != bytesread) {
            exit_code = errno;
            virReportSystemError(errno, "%s",
                                 _("child failed writing to pipe"));
            goto child_cleanup;
        }
    } while (bytesread > 0);
    exit_code = 0;

child_cleanup:
    VIR_FREE(buf);
    VIR_FORCE_CLOSE(fd);
    VIR_FORCE_CLOSE(pipefd[1]);
    _exit(exit_code);
}

static int qemudDomainSaveImageClose(int fd, pid_t read_pid, int *status)
{
    int ret = 0;

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot close file"));
    }

    if (read_pid != -1) {
        /* reap the process that read the file */
        while ((ret = waitpid(read_pid, status, 0)) == -1
               && errno == EINTR) {
            /* empty */
        }
    } else if (status) {
        *status = 0;
    }

    return ret;
}

static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5)
qemudDomainSaveImageOpen(struct qemud_driver *driver,
                         const char *path,
                         virDomainDefPtr *ret_def,
                         struct qemud_save_header *ret_header,
                         pid_t *ret_read_pid)
{
    int fd;
    pid_t read_pid = -1;
    struct qemud_save_header header;
    char *xml = NULL;
    virDomainDefPtr def = NULL;

    if ((fd = open(path, O_RDONLY)) < 0) {
        if ((driver->user == 0) || (getuid() != 0)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("cannot read domain image"));
            goto error;
        }

        /* Opening as root failed, but qemu runs as a different user
           that might have better luck. Create a pipe, then fork a
           child process to run as the qemu user, which will hopefully
           have the necessary authority to read the file. */
        if ((fd = qemudOpenAsUID(path,
                                 driver->user, driver->group, &read_pid)) < 0) {
            /* error already reported */
            goto error;
        }
    }

    if (saferead(fd, &header, sizeof(header)) != sizeof(header)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to read qemu header"));
        goto error;
    }

    if (memcmp(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic)) != 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("image magic is incorrect"));
        goto error;
    }

    if (header.version > QEMUD_SAVE_VERSION) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("image version is not supported (%d > %d)"),
                        header.version, QEMUD_SAVE_VERSION);
        goto error;
    }

    if (header.xml_len <= 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("invalid XML length: %d"), header.xml_len);
        goto error;
    }

    if (VIR_ALLOC_N(xml, header.xml_len) < 0) {
        virReportOOMError();
        goto error;
    }

    if (saferead(fd, xml, header.xml_len) != header.xml_len) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to read XML"));
        goto error;
    }

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to parse XML"));
        goto error;
    }

    VIR_FREE(xml);

    *ret_def = def;
    *ret_header = header;
    *ret_read_pid = read_pid;

    return fd;

error:
    virDomainDefFree(def);
    VIR_FREE(xml);
    qemudDomainSaveImageClose(fd, read_pid, NULL);

    return -1;
}

static int ATTRIBUTE_NONNULL(6)
qemudDomainSaveImageStartVM(virConnectPtr conn,
                            struct qemud_driver *driver,
                            virDomainObjPtr vm,
                            int fd,
                            pid_t read_pid,
                            const struct qemud_save_header *header,
                            const char *path)
{
    int ret = -1;
    virDomainEventPtr event;
    int intermediatefd = -1;
    pid_t intermediate_pid = -1;
    int childstat;
    int wait_ret;
    int status;

    if (header->version == 2) {
        const char *intermediate_argv[3] = { NULL, "-dc", NULL };
        const char *prog = qemudSaveCompressionTypeToString(header->compressed);
        if (prog == NULL) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("Invalid compressed save format %d"),
                            header->compressed);
            goto out;
        }

        if (header->compressed != QEMUD_SAVE_FORMAT_RAW) {
            intermediate_argv[0] = prog;
            intermediatefd = fd;
            fd = -1;
            if (virExec(intermediate_argv, NULL, NULL,
                        &intermediate_pid, intermediatefd, &fd, NULL, 0) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Failed to start decompression binary %s"),
                                intermediate_argv[0]);
                goto out;
            }
        }
    }

    /* Set the migration source and start it up. */
    ret = qemudStartVMDaemon(conn, driver, vm, "stdio", true, fd, path,
                             VIR_VM_OP_RESTORE);

    if (intermediate_pid != -1) {
        /* Wait for intermediate process to exit */
        while (waitpid(intermediate_pid, &childstat, 0) == -1 &&
               errno == EINTR) {
            /* empty */
        }
    }
    VIR_FORCE_CLOSE(intermediatefd);

    wait_ret = qemudDomainSaveImageClose(fd, read_pid, &status);
    fd = -1;
    if (read_pid != -1) {
        if (wait_ret == -1) {
            virReportSystemError(errno,
                                 _("failed to wait for process reading '%s'"),
                                 path);
            ret = -1;
        } else if (!WIFEXITED(status)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("child process exited abnormally reading '%s'"),
                            path);
            ret = -1;
        } else {
            int exit_status = WEXITSTATUS(status);
            if (exit_status != 0) {
                virReportSystemError(exit_status,
                                     _("child process returned error reading '%s'"),
                                     path);
                ret = -1;
            }
        }
    }

    if (ret < 0) {
        qemuDomainStartAudit(vm, "restored", false);
        goto out;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    qemuDomainStartAudit(vm, "restored", true);
    if (event)
        qemuDomainEventQueue(driver, event);


    /* If it was running before, resume it now. */
    if (header->was_running) {
        if (doStartCPUs(driver, vm, conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("failed to resume domain"));
            goto out;
        }
        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto out;
        }
    }

    ret = 0;

out:
    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSavedStateLabel &&
        driver->securityDriver->domainRestoreSavedStateLabel(driver->securityDriver,
                                                             vm, path) == -1)
        VIR_WARN("failed to restore save state label on %s", path);

    return ret;
}

static int qemudDomainRestore(virConnectPtr conn,
                              const char *path) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int fd = -1;
    pid_t read_pid = -1;
    int ret = -1;
    struct qemud_save_header header;

    qemuDriverLock(driver);

    fd = qemudDomainSaveImageOpen(driver, path, &def, &header, &read_pid);
    if (fd < 0)
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, true))) {
        /* virDomainAssignDef already set the error */
        goto cleanup;
    }
    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    ret = qemudDomainSaveImageStartVM(conn, driver, vm, fd,
                                      read_pid, &header, path);

    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;
    else if (ret < 0 && !vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    virDomainDefFree(def);
    qemudDomainSaveImageClose(fd, read_pid, NULL);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemudDomainObjRestore(virConnectPtr conn,
                                 struct qemud_driver *driver,
                                 virDomainObjPtr vm,
                                 const char *path)
{
    virDomainDefPtr def = NULL;
    int fd = -1;
    pid_t read_pid = -1;
    int ret = -1;
    struct qemud_save_header header;

    fd = qemudDomainSaveImageOpen(driver, path, &def, &header, &read_pid);
    if (fd < 0)
        goto cleanup;

    if (STRNEQ(vm->def->name, def->name) ||
        memcmp(vm->def->uuid, def->uuid, VIR_UUID_BUFLEN)) {
        char vm_uuidstr[VIR_UUID_STRING_BUFLEN];
        char def_uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(vm->def->uuid, vm_uuidstr);
        virUUIDFormat(def->uuid, def_uuidstr);
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("cannot restore domain '%s' uuid %s from a file"
                          " which belongs to domain '%s' uuid %s"),
                        vm->def->name, vm_uuidstr,
                        def->name, def_uuidstr);
        goto cleanup;
    }

    virDomainObjAssignDef(vm, def, true);
    def = NULL;

    ret = qemudDomainSaveImageStartVM(conn, driver, vm, fd,
                                      read_pid, &header, path);

cleanup:
    virDomainDefFree(def);
    qemudDomainSaveImageClose(fd, read_pid, NULL);
    return ret;
}


static char *qemudVMDumpXML(struct qemud_driver *driver,
                            virDomainObjPtr vm,
                            int flags)
{
    char *ret = NULL;
    virCPUDefPtr cpu = NULL;
    virDomainDefPtr def;
    virCPUDefPtr def_cpu;

    if ((flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef)
        def = vm->newDef;
    else
        def = vm->def;
    def_cpu = def->cpu;

    /* Update guest CPU requirements according to host CPU */
    if ((flags & VIR_DOMAIN_XML_UPDATE_CPU) && def_cpu && def_cpu->model) {
        if (!driver->caps || !driver->caps->host.cpu) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("cannot get host CPU capabilities"));
            goto cleanup;
        }

        if (!(cpu = virCPUDefCopy(def_cpu))
            || cpuUpdate(cpu, driver->caps->host.cpu))
            goto cleanup;
        def->cpu = cpu;
    }

    ret = virDomainDefFormat(def, flags);

cleanup:
    def->cpu = def_cpu;
    virCPUDefFree(cpu);
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

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    /* Refresh current memory based on balloon info if supported */
    if ((vm->def->memballoon != NULL) &&
        (vm->def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_NONE) &&
        (virDomainObjIsActive(vm))) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        /* Don't delay if someone's using the monitor, just use
         * existing most recent data instead */
        if (!priv->jobActive) {
            if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
                goto cleanup;

            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (qemuDomainObjEndJob(vm) == 0) {
                vm = NULL;
                goto cleanup;
            }
            if (err < 0)
                goto cleanup;
            if (err > 0)
                vm->def->mem.cur_balloon = balloon;
            /* err == 0 indicates no balloon support, so ignore it */
        }
    }

    ret = qemudVMDumpXML(driver, vm, flags);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
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
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        goto cleanup;
    }

    qemuDriverLock(driver);
    def = qemuParseCommandLineString(driver->caps, config);
    qemuDriverUnlock(driver);
    if (!def)
        goto cleanup;

    xml = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE);

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
    virDomainChrDef monConfig;
    unsigned long long qemuCmdFlags;
    virCommandPtr cmd = NULL;
    char *ret = NULL;
    int i;

    qemuDriverLock(driver);

    if (STRNEQ(format, QEMU_CONFIG_FORMAT_ARGV)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        goto cleanup;
    }

    def = virDomainDefParseString(driver->caps, xmlData, 0);
    if (!def)
        goto cleanup;

    /* Since we're just exporting args, we can't do bridge/network/direct
     * setups, since libvirt will normally create TAP/macvtap devices
     * directly. We convert those configs into generic 'ethernet'
     * config and assume the user has suitable 'ifup-qemu' scripts
     */
    for (i = 0 ; i < def->nnets ; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK ||
            net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
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
            def->graphics[i]->data.vnc.port = QEMU_VNC_PORT_MIN;
    }

    if (qemuCapsExtractVersionInfo(def->emulator,
                                   NULL,
                                   &qemuCmdFlags) < 0)
        goto cleanup;

    if (qemuPrepareMonitorChr(driver, &monConfig, def->name) < 0)
        goto cleanup;

    if (!(cmd = qemuBuildCommandLine(conn, driver, def,
                                     &monConfig, false, qemuCmdFlags,
                                     NULL, NULL, VIR_VM_OP_NO_OP)))
        goto cleanup;

    ret = virCommandToString(cmd);

cleanup:
    qemuDriverUnlock(driver);

    virCommandFree(cmd);
    virDomainDefFree(def);
    return ret;
}


static int qemudListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    struct qemud_driver *driver = conn->privateData;
    int n;

    qemuDriverLock(driver);
    n = virDomainObjListGetInactiveNames(&driver->domains, names, nnames);
    qemuDriverUnlock(driver);
    return n;
}

static int qemudNumDefinedDomains(virConnectPtr conn) {
    struct qemud_driver *driver = conn->privateData;
    int n;

    qemuDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 0);
    qemuDriverUnlock(driver);

    return n;
}


static int qemudDomainObjStart(virConnectPtr conn,
                               struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               bool start_paused)
{
    int ret = -1;
    char *managed_save;

    /*
     * If there is a managed saved state restore it instead of starting
     * from scratch. In any case the old state is removed.
     */
    managed_save = qemuDomainManagedSavePath(driver, vm);
    if ((managed_save) && (virFileExists(managed_save))) {
        ret = qemudDomainObjRestore(conn, driver, vm, managed_save);

        if (unlink(managed_save) < 0) {
            VIR_WARN("Failed to remove the managed state %s", managed_save);
        }

        if (ret == 0)
            goto cleanup;
    }

    ret = qemudStartVMDaemon(conn, driver, vm, NULL, start_paused, -1, NULL,
                             VIR_VM_OP_CREATE);
    qemuDomainStartAudit(vm, "booted", ret >= 0);
    if (ret >= 0) {
        virDomainEventPtr event =
            virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
        if (event)
            qemuDomainEventQueue(driver, event);
    }

cleanup:
    VIR_FREE(managed_save);
    return ret;
}

static int
qemudDomainStartWithFlags(virDomainPtr dom, unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is already running"));
        goto endjob;
    }

    ret = qemudDomainObjStart(dom->conn, driver, vm,
                              (flags & VIR_DOMAIN_START_PAUSED) != 0);

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemudDomainStart(virDomainPtr dom)
{
    return qemudDomainStartWithFlags(dom, 0);
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

        if (STRNEQ(def->os.machine, machine->name))
            continue;

        if (!(*canonical = strdup(machine->canonical))) {
            virReportOOMError();
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

    if (qemuCapsProbeMachineTypes(def->emulator, &machines, &nmachines) < 0) {
        virReportOOMError();
        return -1;
    }

    for (i = 0; i < nmachines; i++) {
        if (!machines[i]->canonical)
            continue;

        if (STRNEQ(def->os.machine, machines[i]->name))
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
    int dupVM;

    qemuDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virSecurityDriverVerify(def) < 0)
        goto cleanup;

    if ((dupVM = virDomainObjIsDuplicate(&driver->domains, def, 0)) < 0)
        goto cleanup;

    if (qemudCanonicalizeMachine(driver, def) < 0)
        goto cleanup;

    if (qemuAssignPCIAddresses(def) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, false))) {
        goto cleanup;
    }
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !dupVM ?
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot delete active domain"));
        goto cleanup;
    }

    if (!vm->persistent) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(driver->configDir, driver->autostartDir, vm) < 0)
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


static int qemudDomainAttachDevice(virDomainPtr dom,
                                   const char *xml)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDeviceDefPtr dev = NULL;
    unsigned long long qemuCmdFlags;
    virCgroupPtr cgroup = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot attach device on inactive domain"));
        goto endjob;
    }

    dev = virDomainDeviceDefParse(driver->caps, vm->def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto endjob;

    if (qemuCapsExtractVersionInfo(vm->def->emulator,
                                   NULL,
                                   &qemuCmdFlags) < 0)
        goto endjob;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
            if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) !=0 ) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Unable to find cgroup for %s\n"),
                                vm->def->name);
                goto endjob;
            }
            if (qemuSetupDiskCgroup(driver, cgroup, dev->data.disk) < 0)
                goto endjob;
        }

        switch (dev->data.disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            ret = qemuDomainChangeEjectableMedia(driver, vm,
                                                 dev->data.disk,
                                                 qemuCmdFlags,
                                                 false);
            if (ret == 0)
                dev->data.disk = NULL;
            break;

        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                ret = qemuDomainAttachUsbMassstorageDevice(driver, vm,
                                                           dev->data.disk, qemuCmdFlags);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
                ret = qemuDomainAttachPciDiskDevice(driver, vm,
                                                    dev->data.disk, qemuCmdFlags);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
                ret = qemuDomainAttachSCSIDisk(driver, vm,
                                               dev->data.disk, qemuCmdFlags);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                _("disk bus '%s' cannot be hotplugged."),
                                virDomainDiskBusTypeToString(dev->data.disk->bus));
                /* fallthrough */
            }
            break;

        default:
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("disk device type '%s' cannot be hotplugged"),
                            virDomainDiskDeviceTypeToString(dev->data.disk->device));
            /* Fallthrough */
        }
        if (ret != 0 && cgroup) {
            if (qemuTeardownDiskCgroup(driver, cgroup, dev->data.disk) < 0)
                VIR_WARN("Failed to teardown cgroup for disk path %s",
                         NULLSTR(dev->data.disk->src));
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        if (dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            ret = qemuDomainAttachPciControllerDevice(driver, vm,
                                                      dev->data.controller, qemuCmdFlags);
            if (ret == 0)
                dev->data.controller = NULL;
        } else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("disk controller bus '%s' cannot be hotplugged."),
                            virDomainControllerTypeToString(dev->data.controller->type));
            /* fallthrough */
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        ret = qemuDomainAttachNetDevice(dom->conn, driver, vm,
                                        dev->data.net, qemuCmdFlags);
        if (ret == 0)
            dev->data.net = NULL;
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemuDomainAttachHostDevice(driver, vm,
                                         dev->data.hostdev, qemuCmdFlags);
        if (ret == 0)
            dev->data.hostdev = NULL;
    } else {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("device type '%s' cannot be attached"),
                        virDomainDeviceTypeToString(dev->type));
        goto endjob;
    }

    if (!ret && virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        ret = -1;

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);

    virDomainDeviceDefFree(dev);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemudDomainAttachDeviceFlags(virDomainPtr dom,
                                        const char *xml,
                                        unsigned int flags) {
    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return qemudDomainAttachDevice(dom, xml);
}


static int qemuDomainUpdateDeviceFlags(virDomainPtr dom,
                                       const char *xml,
                                       unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDeviceDefPtr dev = NULL;
    unsigned long long qemuCmdFlags;
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    bool force = (flags & VIR_DOMAIN_DEVICE_MODIFY_FORCE) != 0;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_CURRENT |
                  VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG |
                  VIR_DOMAIN_DEVICE_MODIFY_FORCE, -1);

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot attach device on inactive domain"));
        goto endjob;
    }

    dev = virDomainDeviceDefParse(driver->caps, vm->def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto endjob;

    if (qemuCapsExtractVersionInfo(vm->def->emulator,
                                   NULL,
                                   &qemuCmdFlags) < 0)
        goto endjob;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
            if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) !=0 ) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Unable to find cgroup for %s\n"),
                                vm->def->name);
                goto endjob;
            }
            if (qemuSetupDiskCgroup(driver, cgroup, dev->data.disk) < 0)
                goto endjob;
        }

        switch (dev->data.disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            ret = qemuDomainChangeEjectableMedia(driver, vm,
                                                 dev->data.disk,
                                                 qemuCmdFlags,
                                                 force);
            if (ret == 0)
                dev->data.disk = NULL;
            break;


        default:
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("disk bus '%s' cannot be updated."),
                            virDomainDiskBusTypeToString(dev->data.disk->bus));
            break;
        }

        if (ret != 0 && cgroup) {
            if (qemuTeardownDiskCgroup(driver, cgroup, dev->data.disk) < 0)
                VIR_WARN("Failed to teardown cgroup for disk path %s",
                         NULLSTR(dev->data.disk->src));
        }
        break;

    case VIR_DOMAIN_DEVICE_GRAPHICS:
        ret = qemuDomainChangeGraphics(driver, vm, dev->data.graphics);
        break;

    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("disk device type '%s' cannot be updated"),
                        virDomainDiskDeviceTypeToString(dev->data.disk->device));
        break;
    }

    if (!ret && virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        ret = -1;

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);

    virDomainDeviceDefFree(dev);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}


static int qemudDomainDetachDevice(virDomainPtr dom,
                                   const char *xml) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned long long qemuCmdFlags;
    virDomainDeviceDefPtr dev = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot detach device on inactive domain"));
        goto endjob;
    }

    dev = virDomainDeviceDefParse(driver->caps, vm->def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto endjob;

    if (qemuCapsExtractVersionInfo(vm->def->emulator,
                                   NULL,
                                   &qemuCmdFlags) < 0)
        goto endjob;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
            ret = qemuDomainDetachPciDiskDevice(driver, vm, dev, qemuCmdFlags);
        }
        else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            ret = qemuDomainDetachSCSIDiskDevice(driver, vm, dev,
                                                 qemuCmdFlags);
        }
        else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("This type of disk cannot be hot unplugged"));
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        ret = qemuDomainDetachNetDevice(driver, vm, dev, qemuCmdFlags);
    } else if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        if (dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            ret = qemuDomainDetachPciControllerDevice(driver, vm, dev,
                                                      qemuCmdFlags);
        } else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("disk controller bus '%s' cannot be hotunplugged."),
                            virDomainControllerTypeToString(dev->data.controller->type));
            /* fallthrough */
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemuDomainDetachHostDevice(driver, vm, dev, qemuCmdFlags);
    } else {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        "%s", _("This type of device cannot be hot unplugged"));
    }

    if (!ret && virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        ret = -1;

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    virDomainDeviceDefFree(dev);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemudDomainDetachDeviceFlags(virDomainPtr dom,
                                        const char *xml,
                                        unsigned int flags) {
    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return qemudDomainDetachDevice(dom, xml);
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!vm->persistent) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if ((configFile = virDomainConfigFile(driver->configDir, vm->def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virDomainConfigFile(driver->autostartDir, vm->def->name)) == NULL)
            goto cleanup;

        if (autostart) {
            int err;

            if ((err = virFileMakePath(driver->autostartDir))) {
                virReportSystemError(err,
                                     _("cannot create autostart directory %s"),
                                     driver->autostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
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
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        __FUNCTION__);
        goto cleanup;
    }

    if (nparams)
        *nparams = 1;

    ret = strdup("posix");
    if (!ret)
        virReportOOMError();

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}


static int qemuDomainSetMemoryParameters(virDomainPtr dom,
                                         virMemoryParameterPtr params,
                                         int nparams,
                                         unsigned int flags ATTRIBUTE_UNUSED)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        __FUNCTION__);
        goto cleanup;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < nparams; i++) {
        virMemoryParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT)) {
            int rc;
            if (param->type != VIR_DOMAIN_MEMORY_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for memory hard_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            rc = virCgroupSetMemoryHardLimit(group, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set memory hard_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT)) {
            int rc;
            if (param->type != VIR_DOMAIN_MEMORY_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for memory soft_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            rc = virCgroupSetMemorySoftLimit(group, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set memory soft_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT)) {
            int rc;
            if (param->type != VIR_DOMAIN_MEMORY_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for swap_hard_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            rc = virCgroupSetSwapHardLimit(group, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set swap_hard_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_MIN_GUARANTEE)) {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("Memory tunable `%s' not implemented"), param->field);
            ret = -1;
        } else {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("Parameter `%s' not supported"), param->field);
            ret = -1;
        }
    }

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainGetMemoryParameters(virDomainPtr dom,
                                         virMemoryParameterPtr params,
                                         int *nparams,
                                         unsigned int flags ATTRIBUTE_UNUSED)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long val;
    int ret = -1;
    int rc;

    qemuDriverLock(driver);

    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        __FUNCTION__);
        goto cleanup;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = QEMU_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) != QEMU_NB_MEM_PARAM) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("Invalid parameter count"));
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    for (i = 0; i < *nparams; i++) {
        virMemoryParameterPtr param = &params[i];
        val = 0;
        param->value.ul = 0;
        param->type = VIR_DOMAIN_MEMORY_PARAM_ULLONG;

        switch(i) {
        case 0: /* fill memory hard limit here */
            rc = virCgroupGetMemoryHardLimit(group, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory hard limit"));
                goto cleanup;
            }
            if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("Field memory hard limit too long for destination"));
                goto cleanup;
            }
            param->value.ul = val;
            break;

        case 1: /* fill memory soft limit here */
            rc = virCgroupGetMemorySoftLimit(group, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory soft limit"));
                goto cleanup;
            }
            if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("Field memory soft limit too long for destination"));
                goto cleanup;
            }
            param->value.ul = val;
            break;

        case 2: /* fill swap hard limit here */
            rc = virCgroupGetSwapHardLimit(group, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get swap hard limit"));
                goto cleanup;
            }
            if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("Field swap hard limit too long for destination"));
                goto cleanup;
            }
            param->value.ul = val;
            break;

        default:
            break;
            /* should not hit here */
        }
    }

    ret = 0;

cleanup:
    if (group)
        virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
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
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        __FUNCTION__);
        goto cleanup;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    for (i = 0; i < nparams; i++) {
        virSchedParameterPtr param = &params[i];

        if (STREQ(param->field, "cpu_shares")) {
            int rc;
            if (param->type != VIR_DOMAIN_SCHED_FIELD_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for cpu_shares tunable, expected a 'ullong'"));
                goto cleanup;
            }

            rc = virCgroupSetCpuShares(group, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set cpu shares tunable"));
                goto cleanup;
            }
        } else {
            qemuReportError(VIR_ERR_INVALID_ARG,
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
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        __FUNCTION__);
        goto cleanup;
    }

    if ((*nparams) != 1) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("Invalid parameter count"));
        goto cleanup;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    rc = virCgroupGetCpuShares(group, &val);
    if (rc != 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu shares tunable"));
        goto cleanup;
    }
    params[0].value.ul = val;
    params[0].type = VIR_DOMAIN_SCHED_FIELD_ULLONG;
    if (virStrcpyStatic(params[0].field, "cpu_shares") == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
    int i, ret = -1;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk = NULL;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive (vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(path, vm->def->disks[i]->dst)) {
            disk = vm->def->disks[i];
            break;
        }
    }

    if (!disk) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("invalid path: %s"), path);
        goto endjob;
    }

    if (!disk->info.alias) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("missing disk device alias name for %s"), disk->dst);
        goto endjob;
    }

    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainObjEnterMonitor(vm);
    ret = qemuMonitorGetBlockStatsInfo(priv->mon,
                                       disk->info.alias,
                                       &stats->rd_req,
                                       &stats->rd_bytes,
                                       &stats->wr_req,
                                       &stats->wr_bytes,
                                       &stats->errs);
    qemuDomainObjExitMonitor(vm);

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
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
        ret = linuxDomainInterfaceStats(path, stats);
    else
        qemuReportError(VIR_ERR_INVALID_ARG,
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
    qemuReportError(VIR_ERR_NO_SUPPORT,
                    "%s", __FUNCTION__);
    return -1;
}
#endif

static int
qemudDomainMemoryStats (virDomainPtr dom,
                        struct _virDomainMemoryStat *stats,
                        unsigned int nr_stats)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned int ret = -1;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        qemuDomainObjEnterMonitor(vm);
        ret = qemuMonitorGetMemoryStats(priv->mon, stats, nr_stats);
        qemuDomainObjExitMonitor(vm);
    } else {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
    }

    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!path || path[0] == '\0') {
        qemuReportError(VIR_ERR_INVALID_ARG,
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
            virReportSystemError(errno,
                                 _("%s: failed to open"), path);
            goto cleanup;
        }

        /* Seek and read. */
        /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
         * be 64 bits on all platforms.
         */
        if (lseek (fd, offset, SEEK_SET) == (off_t) -1 ||
            saferead (fd, buffer, size) == (ssize_t) -1) {
            virReportSystemError(errno,
                                 _("%s: failed to seek or read"), path);
            goto cleanup;
        }

        ret = 0;
    } else {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("invalid path"));
    }

cleanup:
    VIR_FORCE_CLOSE(fd);
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (flags != VIR_MEMORY_VIRTUAL && flags != VIR_MEMORY_PHYSICAL) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("flags parameter must be VIR_MEMORY_VIRTUAL or VIR_MEMORY_PHYSICAL"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    if (virAsprintf(&tmp, "%s/qemu.mem.XXXXXX", driver->cacheDir) < 0) {
        virReportOOMError();
        goto endjob;
    }

    /* Create a temporary filename. */
    if ((fd = mkstemp (tmp)) == -1) {
        virReportSystemError(errno,
                             _("mkstemp(\"%s\") failed"), tmp);
        goto endjob;
    }

    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainObjEnterMonitor(vm);
    if (flags == VIR_MEMORY_VIRTUAL) {
        if (qemuMonitorSaveVirtualMemory(priv->mon, offset, size, tmp) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto endjob;
        }
    } else {
        if (qemuMonitorSavePhysicalMemory(priv->mon, offset, size, tmp) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto endjob;
        }
    }
    qemuDomainObjExitMonitor(vm);

    /* Read the memory file into buffer. */
    if (saferead (fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError(errno,
                             _("failed to read temporary file "
                               "created with template %s"), tmp);
        goto endjob;
    }

    ret = 0;

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    VIR_FREE(tmp);
    VIR_FORCE_CLOSE(fd);
    unlink (tmp);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int qemuDomainGetBlockInfo(virDomainPtr dom,
                                  const char *path,
                                  virDomainBlockInfoPtr info,
                                  unsigned int flags) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    int fd = -1;
    off_t end;
    virStorageFileMetadata meta;
    virDomainDiskDefPtr disk = NULL;
    struct stat sb;
    int i;
    int format;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!path || path[0] == '\0') {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("NULL or empty path"));
        goto cleanup;
    }

    /* Check the path belongs to this domain. */
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->src != NULL &&
            STREQ (vm->def->disks[i]->src, path)) {
            disk = vm->def->disks[i];
            break;
        }
    }

    if (!disk) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("invalid path %s not assigned to domain"), path);
        goto cleanup;
    }

    /* The path is correct, now try to open it and get its size. */
    fd = open (path, O_RDONLY);
    if (fd == -1) {
        virReportSystemError(errno,
                             _("failed to open path '%s'"), path);
        goto cleanup;
    }

    /* Probe for magic formats */
    if (disk->driverType) {
        if ((format = virStorageFileFormatTypeFromString(disk->driverType)) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unknown disk format %s for %s"),
                            disk->driverType, disk->src);
            goto cleanup;
        }
    } else {
        if (driver->allowDiskFormatProbing) {
            if ((format = virStorageFileProbeFormat(disk->src)) < 0)
                goto cleanup;
        } else {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("no disk format for %s and probing is disabled"),
                            disk->src);
            goto cleanup;
        }
    }

    if (virStorageFileGetMetadataFromFD(path, fd,
                                        format,
                                        &meta) < 0)
        goto cleanup;

    /* Get info for normal formats */
    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot stat file '%s'"), path);
        goto cleanup;
    }

    if (S_ISREG(sb.st_mode)) {
#ifndef WIN32
        info->physical = (unsigned long long)sb.st_blocks *
            (unsigned long long)DEV_BSIZE;
#else
        info->physical = sb.st_size;
#endif
        /* Regular files may be sparse, so logical size (capacity) is not same
         * as actual physical above
         */
        info->capacity = sb.st_size;
    } else {
        /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
         * be 64 bits on all platforms.
         */
        end = lseek (fd, 0, SEEK_END);
        if (end == (off_t)-1) {
            virReportSystemError(errno,
                                 _("failed to seek to end of %s"), path);
            goto cleanup;
        }
        info->physical = end;
        info->capacity = end;
    }

    /* If the file we probed has a capacity set, then override
     * what we calculated from file/block extents */
    if (meta.capacity)
        info->capacity = meta.capacity;

    /* Set default value .. */
    info->allocation = info->physical;

    /* ..but if guest is running & not using raw
       disk format and on a block device, then query
       highest allocated extent from QEMU */
    if (disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK &&
        format != VIR_STORAGE_FILE_RAW &&
        S_ISBLK(sb.st_mode)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        if (qemuDomainObjBeginJob(vm) < 0)
            goto cleanup;
        if (!virDomainObjIsActive(vm))
            ret = 0;
        else {
            qemuDomainObjEnterMonitor(vm);
            ret = qemuMonitorGetBlockExtent(priv->mon,
                                            disk->info.alias,
                                            &info->allocation);
            qemuDomainObjExitMonitor(vm);
        }

        if (qemuDomainObjEndJob(vm) == 0)
            vm = NULL;
    } else {
        ret = 0;
    }

cleanup:
    VIR_FORCE_CLOSE(fd);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int
qemuDomainEventRegister(virConnectPtr conn,
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
qemuDomainEventDeregister(virConnectPtr conn,
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


static int
qemuDomainEventRegisterAny(virConnectPtr conn,
                           virDomainPtr dom,
                           int eventID,
                           virConnectDomainEventGenericCallback callback,
                           void *opaque,
                           virFreeCallback freecb)
{
    struct qemud_driver *driver = conn->privateData;
    int ret;

    qemuDriverLock(driver);
    ret = virDomainEventCallbackListAddID(conn,
                                          driver->domainEventCallbacks,
                                          dom, eventID,
                                          callback, opaque, freecb);
    qemuDriverUnlock(driver);

    return ret;
}


static int
qemuDomainEventDeregisterAny(virConnectPtr conn,
                             int callbackID)
{
    struct qemud_driver *driver = conn->privateData;
    int ret;

    qemuDriverLock(driver);
    if (driver->domainEventDispatching)
        ret = virDomainEventCallbackListMarkDeleteID(conn, driver->domainEventCallbacks,
                                                     callbackID);
    else
        ret = virDomainEventCallbackListRemoveID(conn, driver->domainEventCallbacks,
                                                 callbackID);
    qemuDriverUnlock(driver);

    return ret;
}


static void qemuDomainEventDispatchFunc(virConnectPtr conn,
                                        virDomainEventPtr event,
                                        virConnectDomainEventGenericCallback cb,
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

static bool ATTRIBUTE_NONNULL(1)
qemuDomainIsMigratable(virDomainDefPtr def)
{
    if (def->nhostdevs > 0) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
            "%s", _("Domain with assigned host devices cannot be migrated"));
        return false;
    }

    return true;
}

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
    unsigned long long qemuCmdFlags;
    qemuDomainObjPrivatePtr priv = NULL;
    struct timeval now;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }

    qemuDriverLock(driver);
    if (!dom_xml) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no domain XML passed"));
        goto cleanup;
    }
    if (!(flags & VIR_MIGRATE_TUNNELLED)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("PrepareTunnel called but no TUNNELLED flag set"));
        goto cleanup;
    }
    if (st == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("tunnelled migration requested but NULL stream passed"));
        goto cleanup;
    }

    /* Parse the domain XML. */
    if (!(def = virDomainDefParseString(driver->caps, dom_xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to parse XML"));
        goto cleanup;
    }

    if (!qemuDomainIsMigratable(def))
        goto cleanup;

    /* Target domain name, maybe renamed. */
    if (dname) {
        VIR_FREE(def->name);
        def->name = strdup(dname);
        if (def->name == NULL)
            goto cleanup;
    }

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, true))) {
        /* virDomainAssignDef already set the error */
        goto cleanup;
    }
    def = NULL;
    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    priv->jobActive = QEMU_JOB_MIGRATION_OUT;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (virAsprintf(&unixfile, "%s/qemu.tunnelmigrate.dest.%s",
                    driver->libDir, vm->def->name) < 0) {
        virReportOOMError();
        goto endjob;
    }
    unlink(unixfile);

    /* check that this qemu version supports the interactive exec */
    if (qemuCapsExtractVersionInfo(vm->def->emulator, NULL, &qemuCmdFlags) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot determine QEMU argv syntax %s"),
                        vm->def->emulator);
        goto endjob;
    }
    if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX)
        internalret = virAsprintf(&migrateFrom, "unix:%s", unixfile);
    else if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC)
        internalret = virAsprintf(&migrateFrom, "exec:nc -U -l %s", unixfile);
    else {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("Destination qemu is too old to support tunnelled migration"));
        goto endjob;
    }
    if (internalret < 0) {
        virReportOOMError();
        goto endjob;
    }
    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming unix:/path/to/file or exec:nc -U /path/to/file
     */
    internalret = qemudStartVMDaemon(dconn, driver, vm, migrateFrom, true,
                                     -1, NULL, VIR_VM_OP_MIGRATE_IN_START);
    VIR_FREE(migrateFrom);
    if (internalret < 0) {
        qemuDomainStartAudit(vm, "migrated", false);
        /* Note that we don't set an error here because qemudStartVMDaemon
         * should have already done that.
         */
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        goto endjob;
    }

    if (virFDStreamConnectUNIX(st,
                               unixfile,
                               false) < 0) {
        qemuDomainStartAudit(vm, "migrated", false);
        qemudShutdownVMDaemon(driver, vm, 0);
        if (!vm->persistent) {
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        virReportSystemError(errno,
                             _("cannot open unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto endjob;
    }

    qemuDomainStartAudit(vm, "migrated", true);

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

    /* We set a fake job active which is held across
     * API calls until the finish() call. This prevents
     * any other APIs being invoked while incoming
     * migration is taking place
     */
    if (vm &&
        virDomainObjIsActive(vm)) {
        priv->jobActive = QEMU_JOB_MIGRATION_IN;
        priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;
        priv->jobStart = timeval_to_ms(now);
    }

cleanup:
    virDomainDefFree(def);
    if (unixfile)
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
static int ATTRIBUTE_NONNULL (5)
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
    char *hostname = NULL;
    char migrateFrom [64];
    const char *p;
    virDomainEventPtr event = NULL;
    int ret = -1;
    int internalret;
    qemuDomainObjPrivatePtr priv = NULL;
    struct timeval now;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }

    virCheckFlags(VIR_MIGRATE_LIVE |
                  VIR_MIGRATE_PEER2PEER |
                  VIR_MIGRATE_TUNNELLED |
                  VIR_MIGRATE_PERSIST_DEST |
                  VIR_MIGRATE_UNDEFINE_SOURCE |
                  VIR_MIGRATE_PAUSED |
                  VIR_MIGRATE_NON_SHARED_DISK |
                  VIR_MIGRATE_NON_SHARED_INC, -1);

    *uri_out = NULL;

    qemuDriverLock(driver);
    if (flags & VIR_MIGRATE_TUNNELLED) {
        /* this is a logical error; we never should have gotten here with
         * VIR_MIGRATE_TUNNELLED set
         */
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Tunnelled migration requested but invalid RPC method called"));
        goto cleanup;
    }

    if (!dom_xml) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
        if ((hostname = virGetHostname(NULL)) == NULL)
            goto cleanup;

        if (STRPREFIX(hostname, "localhost")) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("hostname on destination resolved to localhost, but migration requires an FQDN"));
            goto cleanup;
        }

        /* XXX this really should have been a properly well-formed
         * URI, but we can't add in tcp:// now without breaking
         * compatability with old targets. We at least make the
         * new targets accept both syntaxes though.
         */
        /* Caller frees */
        internalret = virAsprintf(uri_out, "tcp:%s:%d", hostname, this_port);
        if (internalret < 0) {
            virReportOOMError();
            goto cleanup;
        }
    } else {
        /* Check the URI starts with "tcp:".  We will escape the
         * URI when passing it to the qemu monitor, so bad
         * characters in hostname part don't matter.
         */
        if (!STRPREFIX (uri_in, "tcp:")) {
            qemuReportError (VIR_ERR_INVALID_ARG,
                             "%s", _("only tcp URIs are supported for KVM/QEMU migrations"));
            goto cleanup;
        }

        /* Get the port number. */
        p = strrchr (uri_in, ':');
        if (p == strchr(uri_in, ':')) {
            /* Generate a port */
            this_port = QEMUD_MIGRATION_FIRST_PORT + port++;
            if (port == QEMUD_MIGRATION_NUM_PORTS)
                port = 0;

            /* Caller frees */
            if (virAsprintf(uri_out, "%s:%d", uri_in, this_port) < 0) {
                virReportOOMError();
                goto cleanup;
            }

        } else {
            p++; /* definitely has a ':' in it, see above */
            this_port = virParseNumber (&p);
            if (this_port == -1 || p-uri_in != strlen (uri_in)) {
                qemuReportError(VIR_ERR_INVALID_ARG,
                                "%s", _("URI ended with incorrect ':port'"));
                goto cleanup;
            }
        }
    }

    if (*uri_out)
        VIR_DEBUG("Generated uri_out=%s", *uri_out);

    /* Parse the domain XML. */
    if (!(def = virDomainDefParseString(driver->caps, dom_xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to parse XML"));
        goto cleanup;
    }

    if (!qemuDomainIsMigratable(def))
        goto cleanup;

    /* Target domain name, maybe renamed. */
    if (dname) {
        VIR_FREE(def->name);
        def->name = strdup(dname);
        if (def->name == NULL)
            goto cleanup;
    }

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, true))) {
        /* virDomainAssignDef already set the error */
        goto cleanup;
    }
    def = NULL;
    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    priv->jobActive = QEMU_JOB_MIGRATION_OUT;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming tcp:0.0.0.0:port
     */
    snprintf (migrateFrom, sizeof (migrateFrom), "tcp:0.0.0.0:%d", this_port);
    if (qemudStartVMDaemon (dconn, driver, vm, migrateFrom, true,
                            -1, NULL, VIR_VM_OP_MIGRATE_IN_START) < 0) {
        qemuDomainStartAudit(vm, "migrated", false);
        /* Note that we don't set an error here because qemudStartVMDaemon
         * should have already done that.
         */
        if (!vm->persistent) {
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        goto endjob;
    }

    qemuDomainStartAudit(vm, "migrated", true);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

    /* We set a fake job active which is held across
     * API calls until the finish() call. This prevents
     * any other APIs being invoked while incoming
     * migration is taking place
     */
    if (vm &&
        virDomainObjIsActive(vm)) {
        priv->jobActive = QEMU_JOB_MIGRATION_IN;
        priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;
        priv->jobStart = timeval_to_ms(now);
    }

cleanup:
    VIR_FREE(hostname);
    virDomainDefFree(def);
    if (ret != 0)
        VIR_FREE(*uri_out);
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
static int doNativeMigrate(struct qemud_driver *driver,
                           virDomainObjPtr vm,
                           const char *uri,
                           unsigned int flags,
                           const char *dname ATTRIBUTE_UNUSED,
                           unsigned long resource)
{
    int ret = -1;
    xmlURIPtr uribits = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned int background_flags = QEMU_MONITOR_MIGRATE_BACKGROUND;

    /* Issue the migrate command. */
    if (STRPREFIX(uri, "tcp:") && !STRPREFIX(uri, "tcp://")) {
        /* HACK: source host generates bogus URIs, so fix them up */
        char *tmpuri;
        if (virAsprintf(&tmpuri, "tcp://%s", uri + strlen("tcp:")) < 0) {
            virReportOOMError();
            goto cleanup;
        }
        uribits = xmlParseURI(tmpuri);
        VIR_FREE(tmpuri);
    } else {
        uribits = xmlParseURI(uri);
    }
    if (!uribits) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot parse URI %s"), uri);
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (resource > 0 &&
        qemuMonitorSetMigrationSpeed(priv->mon, resource) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_DISK)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_DISK;

    if (flags & VIR_MIGRATE_NON_SHARED_INC)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_INC;

    if (qemuMonitorMigrateToHost(priv->mon, background_flags, uribits->server,
                                 uribits->port) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cleanup;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (qemuDomainWaitForMigrationComplete(driver, vm) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    xmlFreeURI(uribits);
    return ret;
}


#define TUNNEL_SEND_BUF_SIZE 65536

static int doTunnelSendAll(virStreamPtr st,
                           int sock)
{
    char *buffer;
    int nbytes = TUNNEL_SEND_BUF_SIZE;

    if (VIR_ALLOC_N(buffer, TUNNEL_SEND_BUF_SIZE) < 0) {
        virReportOOMError();
        virStreamAbort(st);
        return -1;
    }

    /* XXX should honour the 'resource' parameter here */
    for (;;) {
        nbytes = saferead(sock, buffer, nbytes);
        if (nbytes < 0) {
            virReportSystemError(errno, "%s",
                                 _("tunnelled migration failed to read from qemu"));
            virStreamAbort(st);
            VIR_FREE(buffer);
            return -1;
        }
        else if (nbytes == 0)
            /* EOF; get out of here */
            break;

        if (virStreamSend(st, buffer, nbytes) < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("Failed to write migration data to remote libvirtd"));
            VIR_FREE(buffer);
            return -1;
        }
    }

    VIR_FREE(buffer);

    if (virStreamFinish(st) < 0)
        /* virStreamFinish set the error for us */
        return -1;

    return 0;
}

static int doTunnelMigrate(virDomainPtr dom,
                           struct qemud_driver *driver,
                           virConnectPtr dconn,
                           virDomainObjPtr vm,
                           const char *dom_xml,
                           const char *uri,
                           unsigned long flags,
                           const char *dname,
                           unsigned long resource)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int client_sock = -1;
    int qemu_sock = -1;
    struct sockaddr_un sa_qemu, sa_client;
    socklen_t addrlen;
    virDomainPtr ddomain = NULL;
    int retval = -1;
    virStreamPtr st = NULL;
    char *unixfile = NULL;
    int internalret;
    unsigned long long qemuCmdFlags;
    int status;
    unsigned long long transferred, remaining, total;
    unsigned int background_flags = QEMU_MONITOR_MIGRATE_BACKGROUND;

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
                    driver->libDir, vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemu_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (qemu_sock < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot open tunnelled migration socket"));
        goto cleanup;
    }
    memset(&sa_qemu, 0, sizeof(sa_qemu));
    sa_qemu.sun_family = AF_UNIX;
    if (virStrcpy(sa_qemu.sun_path, unixfile,
                  sizeof(sa_qemu.sun_path)) == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Unix socket '%s' too big for destination"),
                        unixfile);
        goto cleanup;
    }
    unlink(unixfile);
    if (bind(qemu_sock, (struct sockaddr *)&sa_qemu, sizeof(sa_qemu)) < 0) {
        virReportSystemError(errno,
                             _("Cannot bind to unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto cleanup;
    }
    if (listen(qemu_sock, 1) < 0) {
        virReportSystemError(errno,
                             _("Cannot listen on unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto cleanup;
    }

    if (chown(unixfile, qemu_driver->user, qemu_driver->group) < 0) {
        virReportSystemError(errno,
                             _("Cannot change unix socket '%s' owner"),
                             unixfile);
        goto cleanup;
    }

    /* check that this qemu version supports the unix migration */
    if (qemuCapsExtractVersionInfo(vm->def->emulator, NULL, &qemuCmdFlags) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot extract Qemu version from '%s'"),
                        vm->def->emulator);
        goto cleanup;
    }

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX) &&
        !(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
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

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    internalret = dconn->driver->domainMigratePrepareTunnel(dconn, st,
                                                            flags, dname,
                                                            resource, dom_xml);
    qemuDomainObjExitRemoteWithDriver(driver, vm);

    if (internalret < 0)
        /* domainMigratePrepareTunnel sets the error for us */
        goto cleanup;

    /* the domain may have shutdown or crashed while we had the locks dropped
     * in qemuDomainObjEnterRemoteWithDriver, so check again
     */
    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    /*   3. start migration on source */
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (flags & VIR_MIGRATE_NON_SHARED_DISK)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_DISK;
    if (flags & VIR_MIGRATE_NON_SHARED_INC)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_INC;
    if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX){
        internalret = qemuMonitorMigrateToUnix(priv->mon, background_flags,
                                               unixfile);
    }
    else if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC) {
        const char *args[] = { "nc", "-U", unixfile, NULL };
        internalret = qemuMonitorMigrateToCommand(priv->mon, QEMU_MONITOR_MIGRATE_BACKGROUND, args);
    } else {
        internalret = -1;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (internalret < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("tunnelled migration monitor command failed"));
        goto finish;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    /* From this point onwards we *must* call cancel to abort the
     * migration on source if anything goes wrong */

    /* it is also possible that the migrate didn't fail initially, but
     * rather failed later on.  Check the output of "info migrate"
     */
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorGetMigrationStatus(priv->mon,
                                      &status,
                                      &transferred,
                                      &remaining,
                                      &total) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cancel;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (status == QEMU_MONITOR_MIGRATION_STATUS_ERROR) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s",_("migrate failed"));
        goto cancel;
    }

    addrlen = sizeof(sa_client);
    while ((client_sock = accept(qemu_sock, (struct sockaddr *)&sa_client, &addrlen)) < 0) {
        if (errno == EAGAIN || errno == EINTR)
            continue;
        virReportSystemError(errno, "%s",
                             _("tunnelled migration failed to accept from qemu"));
        goto cancel;
    }

    retval = doTunnelSendAll(st, client_sock);

cancel:
    if (retval != 0 && virDomainObjIsActive(vm)) {
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        qemuMonitorMigrateCancel(priv->mon);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

finish:
    dname = dname ? dname : dom->name;
    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, NULL, 0, uri, flags, retval);
    qemuDomainObjExitRemoteWithDriver(driver, vm);

cleanup:
    VIR_FORCE_CLOSE(client_sock);
    VIR_FORCE_CLOSE(qemu_sock);

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
                              struct qemud_driver *driver,
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
    int rc;

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    /* NB we don't pass 'uri' into this, since that's the libvirtd
     * URI in this context - so we let dest pick it */
    rc = dconn->driver->domainMigratePrepare2(dconn,
                                              NULL, /* cookie */
                                              0, /* cookielen */
                                              NULL, /* uri */
                                              &uri_out,
                                              flags, dname,
                                              resource, dom_xml);
    qemuDomainObjExitRemoteWithDriver(driver, vm);
    if (rc < 0)
        /* domainMigratePrepare2 sets the error for us */
        goto cleanup;

    /* the domain may have shutdown or crashed while we had the locks dropped
     * in qemuDomainObjEnterRemoteWithDriver, so check again
     */
    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    if (uri_out == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("domainMigratePrepare2 did not set uri"));
        goto cleanup;
    }

    if (doNativeMigrate(driver, vm, uri_out, flags, dname, resource) < 0)
        goto finish;

    retval = 0;

finish:
    dname = dname ? dname : dom->name;
    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, NULL, 0, uri_out, flags, retval);
    qemuDomainObjExitRemoteWithDriver(driver, vm);

    if (ddomain)
        virUnrefDomain(ddomain);

cleanup:
    return retval;
}


static int doPeer2PeerMigrate(virDomainPtr dom,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *uri,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource)
{
    int ret = -1;
    virConnectPtr dconn = NULL;
    char *dom_xml;
    bool p2p;

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    dconn = virConnectOpen(uri);
    qemuDomainObjExitRemoteWithDriver(driver, vm);
    if (dconn == NULL) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("Failed to connect to remote libvirt URI %s"), uri);
        return -1;
    }

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    p2p = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                   VIR_DRV_FEATURE_MIGRATION_P2P);
    qemuDomainObjExitRemoteWithDriver(driver, vm);
    if (!p2p) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    /* domain may have been stopped while we were talking to remote daemon */
    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    dom_xml = qemudVMDumpXML(driver, vm,
                             VIR_DOMAIN_XML_SECURE |
                             VIR_DOMAIN_XML_UPDATE_CPU);
    if (!dom_xml) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to get domain xml"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = doTunnelMigrate(dom, driver, dconn, vm, dom_xml, uri, flags, dname, resource);
    else
        ret = doNonTunnelMigrate(dom, driver, dconn, vm, dom_xml, uri, flags, dname, resource);

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
    int resume = 0;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_MIGRATE_LIVE |
                  VIR_MIGRATE_PEER2PEER |
                  VIR_MIGRATE_TUNNELLED |
                  VIR_MIGRATE_PERSIST_DEST |
                  VIR_MIGRATE_UNDEFINE_SOURCE |
                  VIR_MIGRATE_PAUSED |
                  VIR_MIGRATE_NON_SHARED_DISK |
                  VIR_MIGRATE_NON_SHARED_INC, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    priv->jobActive = QEMU_JOB_MIGRATION_OUT;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    resume = vm->state == VIR_DOMAIN_RUNNING;
    if (!(flags & VIR_MIGRATE_LIVE) && vm->state == VIR_DOMAIN_RUNNING) {
        if (qemuDomainMigrateOffline(driver, vm) < 0)
            goto endjob;
    }

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        if (doPeer2PeerMigrate(dom, driver, vm, uri, flags, dname, resource) < 0)
            /* doPeer2PeerMigrate already set the error, so just get out */
            goto endjob;
    } else {
        if (doNativeMigrate(driver, vm, uri, flags, dname, resource) < 0)
            goto endjob;
    }

    /* Clean up the source domain. */
    qemudShutdownVMDaemon(driver, vm, 1);
    qemuDomainStopAudit(vm, "migrated");
    resume = 0;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    if (!vm->persistent || (flags & VIR_MIGRATE_UNDEFINE_SOURCE)) {
        virDomainDeleteConfig(driver->configDir, driver->autostartDir, vm);
        if (qemuDomainObjEndJob(vm) > 0)
            virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }
    ret = 0;

endjob:
    if (resume && vm->state == VIR_DOMAIN_PAUSED) {
        /* we got here through some sort of failure; start the domain again */
        if (doStartCPUs(driver, vm, dom->conn) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best
             */
            VIR_ERROR(_("Failed to resume guest %s after failure"),
                      vm->def->name);
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    }
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

#if WITH_MACVTAP
static void
qemudVPAssociatePortProfiles(virDomainDefPtr def) {
    int i;
    int last_good_net = -1;
    virDomainNetDefPtr net;

    for (i = 0; i < def->nnets; i++) {
        net = def->nets[i];
        if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            if (vpAssociatePortProfileId(net->ifname,
                                         net->mac,
                                         net->data.direct.linkdev,
                                         &net->data.direct.virtPortProfile,
                                         def->uuid,
                                         VIR_VM_OP_MIGRATE_IN_FINISH) != 0)
                goto err_exit;
        }
        last_good_net = i;
    }

    return;

err_exit:
    for (i = 0; i < last_good_net; i++) {
        net = def->nets[i];
        if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            vpDisassociatePortProfileId(net->ifname,
                                        net->mac,
                                        net->data.direct.linkdev,
                                        &net->data.direct.virtPortProfile,
                                        VIR_VM_OP_MIGRATE_IN_FINISH);
        }
    }
}
#else /* !WITH_MACVTAP */
static void
qemudVPAssociatePortProfiles(virDomainDefPtr def ATTRIBUTE_UNUSED) { }
#endif /* WITH_MACVTAP */

/* Finish is the third and final step, and it runs on the destination host. */
static virDomainPtr
qemudDomainMigrateFinish2 (virConnectPtr dconn,
                           const char *dname,
                           const char *cookie ATTRIBUTE_UNUSED,
                           int cookielen ATTRIBUTE_UNUSED,
                           const char *uri ATTRIBUTE_UNUSED,
                           unsigned long flags,
                           int retcode)
{
    struct qemud_driver *driver = dconn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    virErrorPtr orig_err;
    int newVM = 1;
    qemuDomainObjPrivatePtr priv = NULL;

    virCheckFlags(VIR_MIGRATE_LIVE |
                  VIR_MIGRATE_PEER2PEER |
                  VIR_MIGRATE_TUNNELLED |
                  VIR_MIGRATE_PERSIST_DEST |
                  VIR_MIGRATE_UNDEFINE_SOURCE |
                  VIR_MIGRATE_PAUSED |
                  VIR_MIGRATE_NON_SHARED_DISK |
                  VIR_MIGRATE_NON_SHARED_INC, NULL);

    /* Migration failed. Save the current error so nothing squashes it */
    orig_err = virSaveLastError();

    qemuDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dname);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching name '%s'"), dname);
        goto cleanup;
    }

    priv = vm->privateData;
    if (priv->jobActive != QEMU_JOB_MIGRATION_IN) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("domain '%s' is not processing incoming migration"), dname);
        goto cleanup;
    }
    priv->jobActive = QEMU_JOB_NONE;
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    /* Did the migration go as planned?  If yes, return the domain
     * object, but if no, clean up the empty qemu process.
     */
    if (retcode == 0) {
        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto cleanup;
        }

        qemudVPAssociatePortProfiles(vm->def);

        if (flags & VIR_MIGRATE_PERSIST_DEST) {
            if (vm->persistent)
                newVM = 0;
            vm->persistent = 1;

            if (virDomainSaveConfig(driver->configDir, vm->def) < 0) {
                /* Hmpf.  Migration was successful, but making it persistent
                 * was not.  If we report successful, then when this domain
                 * shuts down, management tools are in for a surprise.  On the
                 * other hand, if we report failure, then the management tools
                 * might try to restart the domain on the source side, even
                 * though the domain is actually running on the destination.
                 * Return a NULL dom pointer, and hope that this is a rare
                 * situation and management tools are smart.
                 */
                vm = NULL;
                goto endjob;
            }

            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_DEFINED,
                                             newVM ?
                                             VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                             VIR_DOMAIN_EVENT_DEFINED_UPDATED);
            if (event)
                qemuDomainEventQueue(driver, event);
            event = NULL;

        }
        dom = virGetDomain (dconn, vm->def->name, vm->def->uuid);

        if (!(flags & VIR_MIGRATE_PAUSED)) {
            /* run 'cont' on the destination, which allows migration on qemu
             * >= 0.10.6 to work properly.  This isn't strictly necessary on
             * older qemu's, but it also doesn't hurt anything there
             */
            if (doStartCPUs(driver, vm, dconn) < 0) {
                if (virGetLastError() == NULL)
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("resume operation failed"));
                goto endjob;
            }
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        if (vm->state == VIR_DOMAIN_PAUSED) {
            qemuDomainEventQueue(driver, event);
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_SUSPENDED,
                                             VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
        }
        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto endjob;
        }
    } else {
        qemudShutdownVMDaemon(driver, vm, 1);
        qemuDomainStopAudit(vm, "failed");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FAILED);
        if (!vm->persistent) {
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
    }

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
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

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE);
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
        qemuReportError(VIR_ERR_INVALID_ARG,
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
    struct qemud_driver *driver = dev->conn->privateData;
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (qemudNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    qemuDriverLock(driver);
    if (pciDettachDevice(pci, driver->activePciHostdevs) < 0)
        goto out;

    ret = 0;
out:
    qemuDriverUnlock(driver);
    pciFreeDevice(pci);
    return ret;
}

static int
qemudNodeDeviceReAttach (virNodeDevicePtr dev)
{
    struct qemud_driver *driver = dev->conn->privateData;
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (qemudNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    qemuDriverLock(driver);
    if (pciReAttachDevice(pci, driver->activePciHostdevs) < 0)
        goto out;

    ret = 0;
out:
    qemuDriverUnlock(driver);
    pciFreeDevice(pci);
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

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    qemuDriverLock(driver);

    if (pciResetDevice(pci, driver->activePciHostdevs, NULL) < 0)
        goto out;

    ret = 0;
out:
    qemuDriverUnlock(driver);
    pciFreeDevice(pci);
    return ret;
}

static int
qemuCPUCompare(virConnectPtr conn,
               const char *xmlDesc,
               unsigned int flags ATTRIBUTE_UNUSED)
{
    struct qemud_driver *driver = conn->privateData;
    int ret = VIR_CPU_COMPARE_ERROR;

    qemuDriverLock(driver);

    if (!driver->caps || !driver->caps->host.cpu) {
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        "%s", _("cannot get host CPU capabilities"));
    }
    else
        ret = cpuCompareXML(driver->caps->host.cpu, xmlDesc);

    qemuDriverUnlock(driver);

    return ret;
}


static char *
qemuCPUBaseline(virConnectPtr conn ATTRIBUTE_UNUSED,
                const char **xmlCPUs,
                unsigned int ncpus,
                unsigned int flags ATTRIBUTE_UNUSED)
{
    char *cpu;

    cpu = cpuBaselineXML(xmlCPUs, ncpus, NULL, 0);

    return cpu;
}


static int qemuDomainGetJobInfo(virDomainPtr dom,
                                virDomainJobInfoPtr info) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    priv = vm->privateData;

    if (virDomainObjIsActive(vm)) {
        if (priv->jobActive) {
            struct timeval now;

            memcpy(info, &priv->jobInfo, sizeof(*info));

            /* Refresh elapsed time again just to ensure it
             * is fully updated. This is primarily for benefit
             * of incoming migration which we don't currently
             * monitor actively in the background thread
             */
            if (gettimeofday(&now, NULL) < 0) {
                virReportSystemError(errno, "%s",
                                     _("cannot get time of day"));
                goto cleanup;
            }
            info->timeElapsed = timeval_to_ms(now) - priv->jobStart;
        } else {
            memset(info, 0, sizeof(*info));
            info->type = VIR_DOMAIN_JOB_NONE;
        }
    } else {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int qemuDomainAbortJob(virDomainPtr dom) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    priv = vm->privateData;

    if (virDomainObjIsActive(vm)) {
        if (priv->jobActive) {
            VIR_DEBUG("Requesting cancellation of job on vm %s", vm->def->name);
            priv->jobSignals |= QEMU_JOB_SIGNAL_CANCEL;
        } else {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("no job is active on the domain"));
            goto cleanup;
        }
    } else {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int
qemuDomainMigrateSetMaxDowntime(virDomainPtr dom,
                                unsigned long long downtime,
                                unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (priv->jobActive != QEMU_JOB_MIGRATION_OUT) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not being migrated"));
        goto cleanup;
    }

    VIR_DEBUG("Requesting migration downtime change to %llums", downtime);
    priv->jobSignals |= QEMU_JOB_SIGNAL_MIGRATE_DOWNTIME;
    priv->jobSignalsData.migrateDowntime = downtime;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static char *qemuFindQemuImgBinary(void)
{
    char *ret;

    ret = virFindFileInPath("kvm-img");
    if (ret == NULL)
        ret = virFindFileInPath("qemu-img");
    if (ret == NULL)
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("unable to find kvm-img or qemu-img"));

    return ret;
}

static int qemuDomainSnapshotWriteMetadata(virDomainObjPtr vm,
                                           virDomainSnapshotObjPtr snapshot,
                                           char *snapshotDir)
{
    int fd = -1;
    char *newxml = NULL;
    int ret = -1;
    char *snapDir = NULL;
    char *snapFile = NULL;
    int err;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(vm->def->uuid, uuidstr);
    newxml = virDomainSnapshotDefFormat(uuidstr, snapshot->def, 1);
    if (newxml == NULL) {
        virReportOOMError();
        return -1;
    }

    if (virAsprintf(&snapDir, "%s/%s", snapshotDir, vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    err = virFileMakePath(snapDir);
    if (err < 0) {
        virReportSystemError(err, _("cannot create snapshot directory '%s'"),
                             snapDir);
        goto cleanup;
    }

    if (virAsprintf(&snapFile, "%s/%s.xml", snapDir, snapshot->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    fd = open(snapFile, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("failed to create snapshot file '%s'"), snapFile);
        goto cleanup;
    }
    if (safewrite(fd, newxml, strlen(newxml)) != strlen(newxml)) {
        virReportSystemError(errno, _("Failed to write snapshot data to %s"),
                             snapFile);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(snapFile);
    VIR_FREE(snapDir);
    VIR_FREE(newxml);
    VIR_FORCE_CLOSE(fd);
    return ret;
}

static int qemuDomainSnapshotSetCurrentActive(virDomainObjPtr vm,
                                              char *snapshotDir)
{
    if (vm->current_snapshot) {
        vm->current_snapshot->def->active = 1;

        return qemuDomainSnapshotWriteMetadata(vm, vm->current_snapshot,
                                               snapshotDir);
    }

    return 0;
}

static int qemuDomainSnapshotSetCurrentInactive(virDomainObjPtr vm,
                                                char *snapshotDir)
{
    if (vm->current_snapshot) {
        vm->current_snapshot->def->active = 0;

        return qemuDomainSnapshotWriteMetadata(vm, vm->current_snapshot,
                                               snapshotDir);
    }

    return 0;
}


static int qemuDomainSnapshotIsAllowed(virDomainObjPtr vm)
{
    int i;

    /* FIXME: we need to figure out what else here might succeed; in
     * particular, if it's a raw device but on LVM, we could probably make
     * that succeed as well
     */
    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
            (!vm->def->disks[i]->driverType ||
             STRNEQ(vm->def->disks[i]->driverType, "qcow2"))) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            _("Disk '%s' does not support snapshotting"),
                            vm->def->disks[i]->src);
            return 0;
        }
    }

    return 1;
}

static virDomainSnapshotPtr qemuDomainSnapshotCreateXML(virDomainPtr domain,
                                                        const char *xmlDesc,
                                                        unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainSnapshotDefPtr def;
    const char *qemuimgarg[] = { NULL, "snapshot", "-c", NULL, NULL, NULL };
    int i;

    virCheckFlags(0, NULL);

    qemuDriverLock(driver);
    virUUIDFormat(domain->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    /* in a perfect world, we would allow qemu to tell us this.  The problem
     * is that qemu only does this check device-by-device; so if you had a
     * domain that booted from a large qcow2 device, but had a secondary raw
     * device attached, you wouldn't find out that you can't snapshot your
     * guest until *after* it had spent the time to snapshot the boot device.
     * This is probably a bug in qemu, but we'll work around it here for now.
     */
    if (!qemuDomainSnapshotIsAllowed(vm))
        goto cleanup;

    if (!(def = virDomainSnapshotDefParseString(xmlDesc, 1)))
        goto cleanup;

    if (!(snap = virDomainSnapshotAssignDef(&vm->snapshots, def)))
        goto cleanup;

    /* actually do the snapshot */
    if (!virDomainObjIsActive(vm)) {
        qemuimgarg[0] = qemuFindQemuImgBinary();
        if (qemuimgarg[0] == NULL)
            /* qemuFindQemuImgBinary set the error */
            goto cleanup;

        qemuimgarg[3] = snap->def->name;

        for (i = 0; i < vm->def->ndisks; i++) {
            /* FIXME: we also need to handle LVM here */
            /* FIXME: if we fail halfway through this loop, we are in an
             * inconsistent state.  I'm not quite sure what to do about that
             */
            if (vm->def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                if (!vm->def->disks[i]->driverType ||
                    STRNEQ(vm->def->disks[i]->driverType, "qcow2")) {
                    qemuReportError(VIR_ERR_OPERATION_INVALID,
                                    _("Disk device '%s' does not support snapshotting"),
                                    vm->def->disks[i]->info.alias);
                    goto cleanup;
                }

                qemuimgarg[4] = vm->def->disks[i]->src;

                if (virRun(qemuimgarg, NULL) < 0) {
                    virReportSystemError(errno,
                                         _("Failed to run '%s' to create snapshot '%s' from disk '%s'"),
                                         qemuimgarg[0], snap->def->name,
                                         vm->def->disks[i]->src);
                    goto cleanup;
                }
            }
        }
    }
    else {
        qemuDomainObjPrivatePtr priv;
        int ret;

        if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
            goto cleanup;
        priv = vm->privateData;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        ret = qemuMonitorCreateSnapshot(priv->mon, def->name);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        if (qemuDomainObjEndJob(vm) == 0) {
            vm = NULL;
            goto cleanup;
        }
        if (ret < 0)
            goto cleanup;
    }

    snap->def->state = vm->state;

    /* FIXME: if we fail after this point, there's not a whole lot we can
     * do; we've successfully taken the snapshot, and we are now running
     * on it, so we have to go forward the best we can
     */

    if (vm->current_snapshot) {
        def->parent = strdup(vm->current_snapshot->def->name);
        if (def->parent == NULL) {
            virReportOOMError();
            goto cleanup;
        }
    }

    /* Now we set the new current_snapshot for the domain */
    vm->current_snapshot = snap;

    if (qemuDomainSnapshotWriteMetadata(vm, vm->current_snapshot,
                                        driver->snapshotDir) < 0)
        /* qemuDomainSnapshotWriteMetadata set the error */
        goto cleanup;

    snapshot = virGetDomainSnapshot(domain, snap->def->name);

cleanup:
    VIR_FREE(qemuimgarg[0]);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return snapshot;
}

static int qemuDomainSnapshotListNames(virDomainPtr domain, char **names,
                                       int nameslen,
                                       unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    n = virDomainSnapshotObjListGetNames(&vm->snapshots, names, nameslen);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return n;
}

static int qemuDomainSnapshotNum(virDomainPtr domain,
                                 unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    n = virDomainSnapshotObjListNum(&vm->snapshots);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return n;
}

static virDomainSnapshotPtr qemuDomainSnapshotLookupByName(virDomainPtr domain,
                                                           const char *name,
                                                           unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    snap = virDomainSnapshotFindByName(&vm->snapshots, name);
    if (!snap) {
        qemuReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                        _("no snapshot with matching name '%s'"), name);
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, snap->def->name);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return snapshot;
}

static int qemuDomainHasCurrentSnapshot(virDomainPtr domain,
                                        unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = (vm->current_snapshot != NULL);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static virDomainSnapshotPtr qemuDomainSnapshotCurrent(virDomainPtr domain,
                                                      unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!vm->current_snapshot) {
        qemuReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT, "%s",
                        _("the domain does not have a current snapshot"));
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, vm->current_snapshot->def->name);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return snapshot;
}

static char *qemuDomainSnapshotDumpXML(virDomainSnapshotPtr snapshot,
                                       unsigned int flags)
{
    struct qemud_driver *driver = snapshot->domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    char *xml = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virCheckFlags(0, NULL);

    qemuDriverLock(driver);
    virUUIDFormat(snapshot->domain->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, snapshot->domain->uuid);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    snap = virDomainSnapshotFindByName(&vm->snapshots, snapshot->name);
    if (!snap) {
        qemuReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                        _("no domain snapshot with matching name '%s'"),
                        snapshot->name);
        goto cleanup;
    }

    xml = virDomainSnapshotDefFormat(uuidstr, snap->def, 0);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return xml;
}

static int qemuDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                                      unsigned int flags)
{
    struct qemud_driver *driver = snapshot->domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainSnapshotObjPtr snap = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;
    int rc;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    virUUIDFormat(snapshot->domain->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, snapshot->domain->uuid);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    snap = virDomainSnapshotFindByName(&vm->snapshots, snapshot->name);
    if (!snap) {
        qemuReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                        _("no domain snapshot with matching name '%s'"),
                        snapshot->name);
        goto cleanup;
    }

    vm->current_snapshot = snap;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (snap->def->state == VIR_DOMAIN_RUNNING
        || snap->def->state == VIR_DOMAIN_PAUSED) {

        if (virDomainObjIsActive(vm)) {
            priv = vm->privateData;
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            rc = qemuMonitorLoadSnapshot(priv->mon, snap->def->name);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (rc < 0)
                goto endjob;
        }
        else {
            if (qemuDomainSnapshotSetCurrentActive(vm, driver->snapshotDir) < 0)
                goto endjob;

            rc = qemudStartVMDaemon(snapshot->domain->conn, driver, vm, NULL,
                                    false, -1, NULL, VIR_VM_OP_CREATE);
            qemuDomainStartAudit(vm, "from-snapshot", rc >= 0);
            if (qemuDomainSnapshotSetCurrentInactive(vm, driver->snapshotDir) < 0)
                goto endjob;
            if (rc < 0)
                goto endjob;
        }

        if (snap->def->state == VIR_DOMAIN_PAUSED) {
            /* qemu unconditionally starts the domain running again after
             * loadvm, so let's pause it to keep consistency
             */
            rc = doStopCPUs(driver, vm);
            if (rc < 0)
                goto endjob;
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT);
    }
    else {
        /* qemu is a little funny with running guests and the restoration
         * of snapshots.  If the snapshot was taken online,
         * then after a "loadvm" monitor command, the VM is set running
         * again.  If the snapshot was taken offline, then after a "loadvm"
         * monitor command the VM is left paused.  Unpausing it leads to
         * the memory state *before* the loadvm with the disk *after* the
         * loadvm, which obviously is bound to corrupt something.
         * Therefore we destroy the domain and set it to "off" in this case.
         */

        if (virDomainObjIsActive(vm)) {
            qemudShutdownVMDaemon(driver, vm, 0);
            qemuDomainStopAudit(vm, "from-snapshot");
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
            if (!vm->persistent) {
                if (qemuDomainObjEndJob(vm) > 0)
                    virDomainRemoveInactive(&driver->domains, vm);
                vm = NULL;
                goto cleanup;
            }
        }

        if (qemuDomainSnapshotSetCurrentActive(vm, driver->snapshotDir) < 0)
            goto endjob;
    }

    vm->state = snap->def->state;

    ret = 0;

endjob:
    if (vm && qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (event)
        qemuDomainEventQueue(driver, event);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);

    return ret;
}

static int qemuDomainSnapshotDiscard(struct qemud_driver *driver,
                                     virDomainObjPtr vm,
                                     virDomainSnapshotObjPtr snap)
{
    const char *qemuimgarg[] = { NULL, "snapshot", "-d", NULL, NULL, NULL };
    char *snapFile = NULL;
    int ret = -1;
    int i;
    qemuDomainObjPrivatePtr priv;
    virDomainSnapshotObjPtr parentsnap;

    if (!virDomainObjIsActive(vm)) {
        qemuimgarg[0] = qemuFindQemuImgBinary();
        if (qemuimgarg[0] == NULL)
            /* qemuFindQemuImgBinary set the error */
            goto cleanup;

        qemuimgarg[3] = snap->def->name;

        for (i = 0; i < vm->def->ndisks; i++) {
            /* FIXME: we also need to handle LVM here */
            if (vm->def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                if (!vm->def->disks[i]->driverType ||
                    STRNEQ(vm->def->disks[i]->driverType, "qcow2")) {
                    /* we continue on even in the face of error, since other
                     * disks in this VM may have this snapshot in place
                     */
                    continue;
                }

                qemuimgarg[4] = vm->def->disks[i]->src;

                if (virRun(qemuimgarg, NULL) < 0) {
                    /* we continue on even in the face of error, since other
                     * disks in this VM may have this snapshot in place
                     */
                    continue;
                }
            }
        }
    }
    else {
        priv = vm->privateData;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        /* we continue on even in the face of error */
        qemuMonitorDeleteSnapshot(priv->mon, snap->def->name);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

    if (snap == vm->current_snapshot) {
        if (snap->def->parent) {
            parentsnap = virDomainSnapshotFindByName(&vm->snapshots,
                                                     snap->def->parent);
            if (!parentsnap) {
                qemuReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                                _("no domain snapshot parent with matching name '%s'"),
                                snap->def->parent);
                goto cleanup;
            }

            /* Now we set the new current_snapshot for the domain */
            vm->current_snapshot = parentsnap;
        }
        else
            vm->current_snapshot = NULL;
    }

    if (virAsprintf(&snapFile, "%s/%s/%s.xml", driver->snapshotDir,
                    vm->def->name, snap->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    unlink(snapFile);

    virDomainSnapshotObjListRemove(&vm->snapshots, snap);

    ret = 0;

cleanup:
    VIR_FREE(snapFile);
    VIR_FREE(qemuimgarg[0]);

    return ret;
}

struct snap_remove {
    struct qemud_driver *driver;
    virDomainObjPtr vm;
    char *parent;
    int err;
};

static void qemuDomainSnapshotDiscardChildren(void *payload,
                                              const char *name ATTRIBUTE_UNUSED,
                                              void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    struct snap_remove *curr = data;
    struct snap_remove this;

    if (snap->def->parent && STREQ(snap->def->parent, curr->parent)) {
        this.driver = curr->driver;
        this.vm = curr->vm;
        this.parent = snap->def->name;
        this.err = 0;
        virHashForEach(curr->vm->snapshots.objs,
                       qemuDomainSnapshotDiscardChildren, &this);

        if (this.err)
            curr->err = this.err;
        else
            this.err = qemuDomainSnapshotDiscard(curr->driver, curr->vm, snap);
    }
}

struct snap_reparent {
    struct qemud_driver *driver;
    virDomainSnapshotObjPtr snap;
    virDomainObjPtr vm;
    int err;
};

static void
qemuDomainSnapshotReparentChildren(void *payload,
                                   const char *name ATTRIBUTE_UNUSED,
                                   void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    struct snap_reparent *rep = data;

    if (rep->err < 0) {
        return;
    }

    if (snap->def->parent && STREQ(snap->def->parent, rep->snap->def->name)) {
        VIR_FREE(snap->def->parent);

        if (rep->snap->def->parent != NULL) {
            snap->def->parent = strdup(rep->snap->def->parent);

            if (snap->def->parent == NULL) {
                virReportOOMError();
                rep->err = -1;
                return;
            }
        }

        rep->err = qemuDomainSnapshotWriteMetadata(rep->vm, snap,
                                                   rep->driver->snapshotDir);
    }
}

static int qemuDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                                    unsigned int flags)
{
    struct qemud_driver *driver = snapshot->domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainSnapshotObjPtr snap = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    struct snap_remove rem;
    struct snap_reparent rep;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN, -1);

    qemuDriverLock(driver);
    virUUIDFormat(snapshot->domain->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, snapshot->domain->uuid);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    snap = virDomainSnapshotFindByName(&vm->snapshots, snapshot->name);
    if (!snap) {
        qemuReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                        _("no domain snapshot with matching name '%s'"),
                        snapshot->name);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN) {
        rem.driver = driver;
        rem.vm = vm;
        rem.parent = snap->def->name;
        rem.err = 0;
        virHashForEach(vm->snapshots.objs, qemuDomainSnapshotDiscardChildren,
                       &rem);
        if (rem.err < 0)
            goto endjob;
    } else {
        rep.driver = driver;
        rep.snap = snap;
        rep.vm = vm;
        rep.err = 0;
        virHashForEach(vm->snapshots.objs, qemuDomainSnapshotReparentChildren,
                       &rep);
        if (rep.err < 0)
            goto endjob;
    }

    ret = qemuDomainSnapshotDiscard(driver, vm, snap);

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainMonitorCommand(virDomainPtr domain, const char *cmd,
                                    char **result, unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
   }

    priv = vm->privateData;

    if (!priv->monitor_warned) {
        VIR_INFO("Qemu monitor command '%s' executed; libvirt results may be unpredictable!",
                 cmd);
        priv->monitor_warned = 1;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorArbitraryCommand(priv->mon, cmd, result);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (qemuDomainObjEndJob(vm) == 0) {
        vm = NULL;
        goto cleanup;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}


static int
qemuDomainOpenConsole(virDomainPtr dom,
                      const char *devname,
                      virStreamPtr st,
                      unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int ret = -1;
    int i;
    virDomainChrDefPtr chr = NULL;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    virUUIDFormat(dom->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    if (devname) {
        if (vm->def->console &&
            STREQ(devname, vm->def->console->info.alias))
            chr = vm->def->console;
        for (i = 0 ; !chr && i < vm->def->nserials ; i++) {
            if (STREQ(devname, vm->def->serials[i]->info.alias))
                chr = vm->def->serials[i];
        }
        for (i = 0 ; !chr && i < vm->def->nparallels ; i++) {
            if (STREQ(devname, vm->def->parallels[i]->info.alias))
                chr = vm->def->parallels[i];
        }
    } else {
        if (vm->def->console)
            chr = vm->def->console;
        else if (vm->def->nserials)
            chr = vm->def->serials[0];
    }

    if (!chr) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find character device %s"),
                        NULLSTR(devname));
        goto cleanup;
    }

    if (chr->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("character device %s is not using a PTY"),
                        NULLSTR(devname));
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->data.file.path, O_RDWR) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
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
    NULL, /* libvirtVersion (impl. in libvirt.c) */
    virGetHostname, /* getHostname */
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
    NULL, /* domainSetMaxMemory */
    qemudDomainSetMemory, /* domainSetMemory */
    qemudDomainGetInfo, /* domainGetInfo */
    qemudDomainSave, /* domainSave */
    qemudDomainRestore, /* domainRestore */
    qemudDomainCoreDump, /* domainCoreDump */
    qemudDomainSetVcpus, /* domainSetVcpus */
    qemudDomainSetVcpusFlags, /* domainSetVcpusFlags */
    qemudDomainGetVcpusFlags, /* domainGetVcpusFlags */
    qemudDomainPinVcpu, /* domainPinVcpu */
    qemudDomainGetVcpus, /* domainGetVcpus */
    qemudDomainGetMaxVcpus, /* domainGetMaxVcpus */
    qemudDomainGetSecurityLabel, /* domainGetSecurityLabel */
    qemudNodeGetSecurityModel, /* nodeGetSecurityModel */
    qemudDomainDumpXML, /* domainDumpXML */
    qemuDomainXMLFromNative, /* domainXmlFromNative */
    qemuDomainXMLToNative, /* domainXMLToNative */
    qemudListDefinedDomains, /* listDefinedDomains */
    qemudNumDefinedDomains, /* numOfDefinedDomains */
    qemudDomainStart, /* domainCreate */
    qemudDomainStartWithFlags, /* domainCreateWithFlags */
    qemudDomainDefine, /* domainDefineXML */
    qemudDomainUndefine, /* domainUndefine */
    qemudDomainAttachDevice, /* domainAttachDevice */
    qemudDomainAttachDeviceFlags, /* domainAttachDeviceFlags */
    qemudDomainDetachDevice, /* domainDetachDevice */
    qemudDomainDetachDeviceFlags, /* domainDetachDeviceFlags */
    qemuDomainUpdateDeviceFlags, /* domainUpdateDeviceFlags */
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
    qemudDomainMemoryStats, /* domainMemoryStats */
    qemudDomainBlockPeek, /* domainBlockPeek */
    qemudDomainMemoryPeek, /* domainMemoryPeek */
    qemuDomainGetBlockInfo, /* domainGetBlockInfo */
    nodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    nodeGetFreeMemory,  /* getFreeMemory */
    qemuDomainEventRegister, /* domainEventRegister */
    qemuDomainEventDeregister, /* domainEventDeregister */
    qemudDomainMigratePrepare2, /* domainMigratePrepare2 */
    qemudDomainMigrateFinish2, /* domainMigrateFinish2 */
    qemudNodeDeviceDettach, /* nodeDeviceDettach */
    qemudNodeDeviceReAttach, /* nodeDeviceReAttach */
    qemudNodeDeviceReset, /* nodeDeviceReset */
    qemudDomainMigratePrepareTunnel, /* domainMigratePrepareTunnel */
    qemuIsEncrypted, /* isEncrypted */
    qemuIsSecure, /* isSecure */
    qemuDomainIsActive, /* domainIsActive */
    qemuDomainIsPersistent, /* domainIsPersistent */
    qemuDomainIsUpdated, /* domainIsUpdated */
    qemuCPUCompare, /* cpuCompare */
    qemuCPUBaseline, /* cpuBaseline */
    qemuDomainGetJobInfo, /* domainGetJobInfo */
    qemuDomainAbortJob, /* domainAbortJob */
    qemuDomainMigrateSetMaxDowntime, /* domainMigrateSetMaxDowntime */
    qemuDomainEventRegisterAny, /* domainEventRegisterAny */
    qemuDomainEventDeregisterAny, /* domainEventDeregisterAny */
    qemuDomainManagedSave, /* domainManagedSave */
    qemuDomainHasManagedSaveImage, /* domainHasManagedSaveImage */
    qemuDomainManagedSaveRemove, /* domainManagedSaveRemove */
    qemuDomainSnapshotCreateXML, /* domainSnapshotCreateXML */
    qemuDomainSnapshotDumpXML, /* domainSnapshotDumpXML */
    qemuDomainSnapshotNum, /* domainSnapshotNum */
    qemuDomainSnapshotListNames, /* domainSnapshotListNames */
    qemuDomainSnapshotLookupByName, /* domainSnapshotLookupByName */
    qemuDomainHasCurrentSnapshot, /* domainHasCurrentSnapshot */
    qemuDomainSnapshotCurrent, /* domainSnapshotCurrent */
    qemuDomainRevertToSnapshot, /* domainRevertToSnapshot */
    qemuDomainSnapshotDelete, /* domainSnapshotDelete */
    qemuDomainMonitorCommand, /* qemuDomainMonitorCommand */
    qemuDomainSetMemoryParameters, /* domainSetMemoryParameters */
    qemuDomainGetMemoryParameters, /* domainGetMemoryParameters */
    qemuDomainOpenConsole, /* domainOpenConsole */
};


static virStateDriver qemuStateDriver = {
    .name = "QEMU",
    .initialize = qemudStartup,
    .cleanup = qemudShutdown,
    .reload = qemudReload,
    .active = qemudActive,
};

static int
qemudVMFilterRebuild(virConnectPtr conn ATTRIBUTE_UNUSED,
                     virHashIterator iter, void *data)
{
    virHashForEach(qemu_driver->domains.objs, iter, data);

    return 0;
}

static int
qemudVMFiltersInstantiate(virConnectPtr conn,
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


static void
qemudVMDriverLock(void) {
    qemuDriverLock(qemu_driver);
};


static void
qemudVMDriverUnlock(void) {
    qemuDriverUnlock(qemu_driver);
};


static virNWFilterCallbackDriver qemuCallbackDriver = {
    .name = "QEMU",
    .vmFilterRebuild = qemudVMFilterRebuild,
    .vmDriverLock = qemudVMDriverLock,
    .vmDriverUnlock = qemudVMDriverUnlock,
};

int qemuRegister(void) {
    virRegisterDriver(&qemuDriver);
    virRegisterStateDriver(&qemuStateDriver);
    virNWFilterRegisterCallbackDriver(&qemuCallbackDriver);
    return 0;
}
