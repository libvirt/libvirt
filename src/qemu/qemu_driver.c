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

#ifdef __linux__
#include <sys/vfs.h>
#ifndef NFS_SUPER_MAGIC
#define NFS_SUPER_MAGIC 0x6969
#endif /* NFS_SUPER_MAGIC */
#endif /* __linux__ */

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "qemu_driver.h"
#include "qemu_conf.h"
#include "qemu_monitor.h"
#include "qemu_monitor_text.h"
#include "qemu_bridge_filter.h"
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
#include "cgroup.h"
#include "libvirt_internal.h"
#include "xml.h"
#include "cpu/cpu.h"
#include "macvtap.h"


#define VIR_FROM_THIS VIR_FROM_QEMU

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
typedef qemuDomainObjPrivate *qemuDomainObjPrivatePtr;
struct _qemuDomainObjPrivate {
    virCond jobCond; /* Use in conjunction with main virDomainObjPtr lock */
    unsigned int jobActive : 1; /* Non-zero if a job is active. Only 1 job is allowed at any time
                                 * A job includes *all* monitor commands, even those just querying
                                 * information, not merely actions */
    unsigned int jobCancel : 1; /* Non-zero if a cancel request from client has arrived */
    virDomainJobInfo jobInfo;
    unsigned long long jobStart;

    qemuMonitorPtr mon;
    virDomainChrDefPtr monConfig;
    int monJSON;

    int nvcpupids;
    int *vcpupids;

    qemuDomainPCIAddressSetPtr pciaddrs;
    int persistentAddrs;
};

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

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom,
                              int stdin_fd);

static void qemudShutdownVMDaemon(struct qemud_driver *driver,
                                  virDomainObjPtr vm);

static int qemudDomainGetMaxVcpus(virDomainPtr dom);

static int qemuDetectVcpuPIDs(struct qemud_driver *driver,
                              virDomainObjPtr vm);

static int qemuUpdateActivePciHostdevs(struct qemud_driver *driver,
                                       virDomainDefPtr def);

static struct qemud_driver *qemu_driver = NULL;


static void *qemuDomainObjPrivateAlloc(void)
{
    qemuDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    return priv;
}

static void qemuDomainObjPrivateFree(void *data)
{
    qemuDomainObjPrivatePtr priv = data;

    qemuDomainPCIAddressSetFree(priv->pciaddrs);
    virDomainChrDefFree(priv->monConfig);
    VIR_FREE(priv->vcpupids);

    /* This should never be non-NULL if we get here, but just in case... */
    if (priv->mon) {
        VIR_ERROR0("Unexpected QEMU monitor still active during domain deletion");
        qemuMonitorClose(priv->mon);
    }
    VIR_FREE(priv);
}


static int qemuDomainObjPrivateXMLFormat(virBufferPtr buf, void *data)
{
    qemuDomainObjPrivatePtr priv = data;
    const char *monitorpath;

    /* priv->monitor_chr is set only for qemu */
    if (priv->monConfig) {
        switch (priv->monConfig->type) {
        case VIR_DOMAIN_CHR_TYPE_UNIX:
            monitorpath = priv->monConfig->data.nix.path;
            break;
        default:
        case VIR_DOMAIN_CHR_TYPE_PTY:
            monitorpath = priv->monConfig->data.file.path;
            break;
        }

        virBufferEscapeString(buf, "  <monitor path='%s'", monitorpath);
        if (priv->monJSON)
            virBufferAddLit(buf, " json='1'");
        virBufferVSprintf(buf, " type='%s'/>\n",
                          virDomainChrTypeToString(priv->monConfig->type));
    }


    if (priv->nvcpupids) {
        int i;
        virBufferAddLit(buf, "  <vcpus>\n");
        for (i = 0 ; i < priv->nvcpupids ; i++) {
            virBufferVSprintf(buf, "    <vcpu pid='%d'/>\n", priv->vcpupids[i]);
        }
        virBufferAddLit(buf, "  </vcpus>\n");
    }

    return 0;
}

static int qemuDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt, void *data)
{
    qemuDomainObjPrivatePtr priv = data;
    char *monitorpath;
    char *tmp;
    int n, i;
    xmlNodePtr *nodes = NULL;

    if (VIR_ALLOC(priv->monConfig) < 0) {
        virReportOOMError();
        goto error;
    }

    if (!(priv->monConfig->info.alias = strdup("monitor"))) {
        virReportOOMError();
        goto error;
    }

    if (!(monitorpath =
          virXPathString("string(./monitor[1]/@path)", ctxt))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no monitor path"));
        goto error;
    }

    tmp = virXPathString("string(./monitor[1]/@type)", ctxt);
    if (tmp)
        priv->monConfig->type = virDomainChrTypeFromString(tmp);
    else
        priv->monConfig->type = VIR_DOMAIN_CHR_TYPE_PTY;
    VIR_FREE(tmp);

    if (virXPathBoolean("count(./monitor[@json = '1']) > 0", ctxt)) {
        priv->monJSON = 1;
    } else {
        priv->monJSON = 0;
    }

    switch (priv->monConfig->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        priv->monConfig->data.file.path = monitorpath;
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        priv->monConfig->data.nix.path = monitorpath;
        break;
    default:
        VIR_FREE(monitorpath);
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unsupported monitor type '%s'"),
                        virDomainChrTypeToString(priv->monConfig->type));
        goto error;
    }

    n = virXPathNodeSet("./vcpus/vcpu", ctxt, &nodes);
    if (n < 0)
        goto error;
    if (n) {
        priv->nvcpupids = n;
        if (VIR_REALLOC_N(priv->vcpupids, priv->nvcpupids) < 0) {
            virReportOOMError();
            goto error;
        }

        for (i = 0 ; i < n ; i++) {
            char *pidstr = virXMLPropString(nodes[i], "pid");
            if (!pidstr)
                goto error;

            if (virStrToLong_i(pidstr, NULL, 10, &(priv->vcpupids[i])) < 0) {
                VIR_FREE(pidstr);
                goto error;
            }
            VIR_FREE(pidstr);
        }
        VIR_FREE(nodes);
    }

    return 0;

error:
    virDomainChrDefFree(priv->monConfig);
    priv->monConfig = NULL;
    VIR_FREE(nodes);
    return -1;
}



/*
 * obj must be locked before calling, qemud_driver must NOT be locked
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the QEMU monitor.
 *
 * Upon successful return, the object will have its ref count increased,
 * successful calls must be followed by EndJob eventually
 */

/* Give up waiting for mutex after 30 seconds */
#define QEMU_JOB_WAIT_TIME (1000ull * 30)

static int qemuDomainObjBeginJob(virDomainObjPtr obj) ATTRIBUTE_RETURN_CHECK;
static int qemuDomainObjBeginJob(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    struct timeval now;
    unsigned long long then;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }
    then = (now.tv_sec * 1000ull) + (now.tv_usec / 1000);
    then += QEMU_JOB_WAIT_TIME;

    virDomainObjRef(obj);

    while (priv->jobActive) {
        if (virCondWaitUntil(&priv->jobCond, &obj->lock, then) < 0) {
            virDomainObjUnref(obj);
            if (errno == ETIMEDOUT)
                qemuReportError(VIR_ERR_OPERATION_TIMEOUT,
                                "%s", _("cannot acquire state change lock"));
            else
                virReportSystemError(errno,
                                     "%s", _("cannot acquire job mutex"));
            return -1;
        }
    }
    priv->jobActive = 1;
    priv->jobCancel = 0;
    priv->jobStart = (now.tv_sec * 1000ull) + (now.tv_usec / 1000);
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));

    return 0;
}

/*
 * obj must be locked before calling, qemud_driver must be locked
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the QEMU monitor.
 */
static int qemuDomainObjBeginJobWithDriver(struct qemud_driver *driver,
                                           virDomainObjPtr obj) ATTRIBUTE_RETURN_CHECK;
static int qemuDomainObjBeginJobWithDriver(struct qemud_driver *driver,
                                           virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    struct timeval now;
    unsigned long long then;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }
    then = (now.tv_sec * 1000ull) + (now.tv_usec / 1000);
    then += QEMU_JOB_WAIT_TIME;

    virDomainObjRef(obj);
    qemuDriverUnlock(driver);

    while (priv->jobActive) {
        if (virCondWaitUntil(&priv->jobCond, &obj->lock, then) < 0) {
            virDomainObjUnref(obj);
            if (errno == ETIMEDOUT)
                qemuReportError(VIR_ERR_OPERATION_TIMEOUT,
                                "%s", _("cannot acquire state change lock"));
            else
                virReportSystemError(errno,
                                     "%s", _("cannot acquire job mutex"));
            qemuDriverLock(driver);
            return -1;
        }
    }
    priv->jobActive = 1;
    priv->jobCancel = 0;
    priv->jobStart = (now.tv_sec * 1000ull) + (now.tv_usec / 1000);
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));

    virDomainObjUnlock(obj);
    qemuDriverLock(driver);
    virDomainObjLock(obj);

    return 0;
}

/*
 * obj must be locked before calling, qemud_driver does not matter
 *
 * To be called after completing the work associated with the
 * earlier  qemuDomainBeginJob() call
 *
 * Returns remaining refcount on 'obj', maybe 0 to indicated it
 * was deleted
 */
static int ATTRIBUTE_RETURN_CHECK qemuDomainObjEndJob(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    priv->jobActive = 0;
    priv->jobCancel = 0;
    priv->jobStart = 0;
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    virCondSignal(&priv->jobCond);

    return virDomainObjUnref(obj);
}


/*
 * obj must be locked before calling, qemud_driver must be unlocked
 *
 * To be called immediately before any QEMU monitor API call
 * Must have alrady called qemuDomainObjBeginJob().
 *
 * To be followed with qemuDomainObjExitMonitor() once complete
 */
static void qemuDomainObjEnterMonitor(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    qemuMonitorLock(priv->mon);
    qemuMonitorRef(priv->mon);
    virDomainObjUnlock(obj);
}


/* obj must NOT be locked before calling, qemud_driver must be unlocked
 *
 * Should be paired with an earlier  qemuDomainObjEnterMonitor() call
 */
static void qemuDomainObjExitMonitor(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    int refs;

    refs = qemuMonitorUnref(priv->mon);

    if (refs > 0)
        qemuMonitorUnlock(priv->mon);

    virDomainObjLock(obj);

    if (refs == 0) {
        virDomainObjUnref(obj);
        priv->mon = NULL;
    }
}


/*
 * obj must be locked before calling, qemud_driver must be locked
 *
 * To be called immediately before any QEMU monitor API call
 * Must have alrady called qemuDomainObjBeginJob().
 *
 * To be followed with qemuDomainObjExitMonitorWithDriver() once complete
 */
static void qemuDomainObjEnterMonitorWithDriver(struct qemud_driver *driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    qemuMonitorLock(priv->mon);
    qemuMonitorRef(priv->mon);
    virDomainObjUnlock(obj);
    qemuDriverUnlock(driver);
}


/* obj must NOT be locked before calling, qemud_driver must be unlocked,
 * and will be locked after returning
 *
 * Should be paired with an earlier  qemuDomainObjEnterMonitor() call
 */
static void qemuDomainObjExitMonitorWithDriver(struct qemud_driver *driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    int refs;

    refs = qemuMonitorUnref(priv->mon);

    if (refs > 0)
        qemuMonitorUnlock(priv->mon);

    qemuDriverLock(driver);
    virDomainObjLock(obj);

    if (refs == 0) {
        virDomainObjUnref(obj);
        priv->mon = NULL;
    }
}


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
qemudLogFD(struct qemud_driver *driver, const char* name)
{
    char logfile[PATH_MAX];
    mode_t logmode;
    int ret, fd = -1;

    if ((ret = snprintf(logfile, sizeof(logfile), "%s/%s.log",
                        driver->logDir, name))
        < 0 || ret >= sizeof(logfile)) {
        virReportOOMError();
        return -1;
    }

    logmode = O_CREAT | O_WRONLY;
    /* Only logrotate files in /var/log, so only append if running privileged */
    if (driver->privileged)
        logmode |= O_APPEND;
    else
        logmode |= O_TRUNC;

    if ((fd = open(logfile, logmode, S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("failed to create logfile %s"),
                             logfile);
        return -1;
    }
    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set VM logfile close-on-exec flag"));
        close(fd);
        return -1;
    }
    return fd;
}


static int
qemudLogReadFD(const char* logDir, const char* name, off_t pos)
{
    char logfile[PATH_MAX];
    mode_t logmode = O_RDONLY;
    int ret, fd = -1;

    if ((ret = snprintf(logfile, sizeof(logfile), "%s/%s.log", logDir, name))
        < 0 || ret >= sizeof(logfile)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("failed to build logfile name %s/%s.log"),
                        logDir, name);
        return -1;
    }


    if ((fd = open(logfile, logmode)) < 0) {
        virReportSystemError(errno,
                             _("failed to create logfile %s"),
                             logfile);
        return -1;
    }
    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set VM logfile close-on-exec flag"));
        close(fd);
        return -1;
    }
    if (pos < 0 || lseek(fd, pos, SEEK_SET) < 0) {
      virReportSystemError(pos < 0 ? 0 : errno,
                             _("Unable to seek to %lld in %s"),
                             (long long) pos, logfile);
        close(fd);
    }
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

    virDomainObjLock(vm);
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        int ret;

        virResetLastError();
        ret = qemudStartVMDaemon(data->conn, data->driver, vm, NULL, -1);
        if (ret < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : "");
        } else {
            virDomainEventPtr event =
                virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
            if (event)
                qemuDomainEventQueue(data->driver, event);
        }
    }
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
        VIR_WARN(_("Failed to remove domain XML for %s: %s"),
                 vm->def->name, virStrerror(errno, ebuf, sizeof(ebuf)));
    VIR_FREE(file);

    if (virFileDeletePid(driver->stateDir, vm->def->name) != 0)
        VIR_WARN(_("Failed to remove PID file for %s: %s"),
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

    VIR_DEBUG("Received EOF on %p '%s'", vm, vm->def->name);
    virDomainObjLock(vm);

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     hasError ?
                                     VIR_DOMAIN_EVENT_STOPPED_FAILED :
                                     VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);

    qemudShutdownVMDaemon(driver, vm);
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
        qemuReportError(VIR_ERR_NO_SUPPORT,
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

static qemuMonitorCallbacks monitorCallbacks = {
    .eofNotify = qemuHandleMonitorEOF,
    .diskSecretLookup = findVolumeQcowPassphrase,
};

static int
qemuConnectMonitor(struct qemud_driver *driver, virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted while the monitor is active */
    virDomainObjRef(vm);

    if ((priv->mon = qemuMonitorOpen(vm,
                                     priv->monConfig,
                                     priv->monJSON,
                                     &monitorCallbacks)) == NULL) {
        VIR_ERROR(_("Failed to connect monitor for %s"), vm->def->name);
        return -1;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorSetCapabilities(priv->mon);
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (ret < 0) {
        qemuMonitorClose(priv->mon);
        priv->mon = NULL;
    }

    return ret;
}

/*
 * Open an existing VM's monitor, re-detect VCPU threads
 * and re-reserve the security labels in use
 */
static void
qemuReconnectDomain(void *payload, const char *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr obj = payload;
    struct qemud_driver *driver = opaque;
    qemuDomainObjPrivatePtr priv;
    unsigned long long qemuCmdFlags;

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
    if (qemudExtractVersionInfo(obj->def->emulator,
                                NULL,
                                &qemuCmdFlags) >= 0 &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE))
        priv->persistentAddrs = 1;

    if (!(priv->pciaddrs = qemuDomainPCIAddressSetCreate(obj->def)))
        goto error;

    if (driver->securityDriver &&
        driver->securityDriver->domainReserveSecurityLabel &&
        driver->securityDriver->domainReserveSecurityLabel(obj) < 0)
        goto error;

    if (obj->def->id >= driver->nextvmid)
        driver->nextvmid = obj->def->id + 1;

    virDomainObjUnlock(obj);
    return;

error:
    /* We can't get the monitor back, so must kill the VM
     * to remove danger of it ending up running twice if
     * user tries to start it again later */
    qemudShutdownVMDaemon(driver, obj);
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
qemuReconnectDomains(struct qemud_driver *driver)
{
    virHashForEach(driver->domains.objs, qemuReconnectDomain, driver);
}


static int
qemudSecurityInit(struct qemud_driver *qemud_drv)
{
    int ret;
    virSecurityDriverPtr security_drv;

    qemuSecurityStackedSetDriver(qemud_drv);
    qemuSecurityDACSetDriver(qemud_drv);

    ret = virSecurityDriverStartup(&security_drv,
                                   qemud_drv->securityDriverName);
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
    if (!(caps = qemudCapsInit(oldcaps))) {
        virReportOOMError();
        return NULL;
    }

    /* Domain XML parser hooks */
    caps->privateDataAllocFunc = qemuDomainObjPrivateAlloc;
    caps->privateDataFreeFunc = qemuDomainObjPrivateFree;
    caps->privateDataXMLFormat = qemuDomainObjPrivateXMLFormat;
    caps->privateDataXMLParse = qemuDomainObjPrivateXMLParse;


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
    virCapabilitiesFree(caps);
    return NULL;
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

    if (qemudLoadDriverConfig(qemu_driver, driverConf) < 0) {
        goto error;
    }

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

    qemuReconnectDomains(qemu_driver);

    /* Then inactive persistent configs */
    if (virDomainLoadAllConfigs(qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->configDir,
                                qemu_driver->autostartDir,
                                0, NULL, NULL) < 0)
        goto error;
    qemuDriverUnlock(qemu_driver);

    qemudAutostartConfigs(qemu_driver);


    return 0;

out_of_memory:
    virReportOOMError();
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

static int
qemudWaitForMonitor(struct qemud_driver* driver,
                    virDomainObjPtr vm, off_t pos)
{
    char buf[4096]; /* Plenty of space to get startup greeting */
    int logfd;
    int ret = -1;

    if ((logfd = qemudLogReadFD(driver->logDir, vm->def->name, pos))
        < 0)
        return -1;

    ret = qemudReadLogOutput(vm, logfd, buf, sizeof(buf),
                             qemudFindCharDevicePTYs,
                             "console", 30);
    if (close(logfd) < 0) {
        char ebuf[4096];
        VIR_WARN(_("Unable to close logfile: %s"),
                 virStrerror(errno, ebuf, sizeof ebuf));
    }

    if (ret < 0)
        return -1;

    VIR_DEBUG("Connect monitor to %p '%s'", vm, vm->def->name);
    if (qemuConnectMonitor(driver, vm) < 0)
        return -1;

    /* Try to get the pty path mappings again via the monitor. This is much more
     * reliable if it's available.
     * Note that the monitor itself can be on a pty, so we still need to try the
     * log output method. */
    virHashTablePtr paths = virHashCreate(0);
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
                        _("got wrong number of vCPU pids from QEMU monitor. got %d, wanted %d"),
                        ncpupids, (int)vm->def->vcpus);
        VIR_FREE(cpupids);
        return -1;
    }

    priv->nvcpupids = ncpupids;
    priv->vcpupids = cpupids;
    return 0;
}

static int
qemudInitCpuAffinity(virDomainObjPtr vm)
{
    int i, hostcpus, maxcpu = QEMUD_CPUMASK_LEN;
    virNodeInfo nodeinfo;
    unsigned char *cpumap;
    int cpumaplen;
    qemuDomainObjPrivatePtr priv = vm->privateData;

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

    /* The XML config only gives a per-VM affinity, so we apply
     * the same mapping to all vCPUs */
    for (i = 0 ; i < priv->nvcpupids ; i++) {
        if (virProcessInfoSetAffinity(priv->vcpupids[i],
                                      cpumap, cpumaplen, maxcpu) < 0) {
            VIR_FREE(cpumap);
            return -1;
        }
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
        (vm->def->graphics[0]->data.vnc.passwd || driver->vncPassword)) {

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        ret = qemuMonitorSetVNCPassword(priv->mon,
                                        vm->def->graphics[0]->data.vnc.passwd ?
                                        vm->def->graphics[0]->data.vnc.passwd :
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

    /* XXX console (virtio) */


    /* ... and now things we don't have in our xml */

    /* XXX USB controller ? */

    /* XXXX virtio balloon ? */

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


static int
qemuAssignPCIAddresses(virDomainDefPtr def)
{
    int ret = -1;
    unsigned long long qemuCmdFlags = 0;
    qemuDomainPCIAddressSetPtr addrs = NULL;
    struct stat sb;

    if (stat(def->emulator, &sb) < 0) {
        virReportSystemError(errno,
                             _("Cannot find QEMU binary %s"),
                             def->emulator);
        goto cleanup;
    }

    if (qemudExtractVersionInfo(def->emulator,
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


static pciDeviceList *
qemuGetPciHostDeviceList(virDomainDefPtr def)
{
    pciDeviceList *list;
    int i;

    if (!(list = pciDeviceListNew()))
        return NULL;

    for (i = 0 ; i < def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        pciDevice *dev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = pciGetDevice(hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);
        if (!dev) {
            pciDeviceListFree(list);
            return NULL;
        }

        if (pciDeviceListAdd(list, dev) < 0) {
            pciFreeDevice(dev);
            pciDeviceListFree(list);
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
    int i;
    int ret = -1;

    if (!def->nhostdevs)
        return 0;

    if (!(pcidevs = qemuGetPciHostDeviceList(def)))
        return -1;

    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        pciDeviceListSteal(pcidevs, dev);
        if (pciDeviceListAdd(driver->activePciHostdevs, dev) < 0) {
            pciFreeDevice(dev);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    pciDeviceListFree(pcidevs);
    return ret;
}


static int
qemuPrepareHostPCIDevices(struct qemud_driver *driver,
                          virDomainDefPtr def)
{
    pciDeviceList *pcidevs;
    int i;
    int ret = -1;

    if (!(pcidevs = qemuGetPciHostDeviceList(def)))
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

    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        if (!pciDeviceIsAssignable(dev, !driver->relaxedACS))
            goto cleanup;

        if (pciDeviceGetManaged(dev) &&
            pciDettachDevice(dev) < 0)
            goto cleanup;
    }

    /* Now that all the PCI hostdevs have be dettached, we can safely
     * reset them */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        if (pciResetDevice(dev, driver->activePciHostdevs) < 0)
            goto cleanup;
    }

    /* Now mark all the devices as active */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        pciDeviceListSteal(pcidevs, dev);
        if (pciDeviceListAdd(driver->activePciHostdevs, dev) < 0) {
            pciFreeDevice(dev);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    pciDeviceListFree(pcidevs);
    return ret;
}


static int
qemuPrepareHostUSBDevices(struct qemud_driver *driver ATTRIBUTE_UNUSED,
                          virDomainDefPtr def)
{
    int i;
    for (i = 0 ; i < def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        /* Resolve a vendor/product to bus/device */
        if (hostdev->source.subsys.u.usb.vendor) {
            usbDevice *usb
                = usbFindDevice(hostdev->source.subsys.u.usb.vendor,
                                hostdev->source.subsys.u.usb.product);

            if (!usb)
                return -1;

            hostdev->source.subsys.u.usb.bus = usbDeviceGetBus(usb);
            hostdev->source.subsys.u.usb.device = usbDeviceGetDevno(usb);

            usbFreeDevice(usb);
        }
    }

    return 0;
}

static int
qemuPrepareHostDevices(struct qemud_driver *driver,
                       virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return 0;

    if (qemuPrepareHostPCIDevices(driver, def) < 0)
        return -1;

    if (qemuPrepareHostUSBDevices(driver, def) < 0)
        return -1;

    return 0;
}


static void
qemudReattachManagedDevice(pciDevice *dev)
{
    int retries = 100;

    if (pciDeviceGetManaged(dev)) {
        while (pciWaitForDeviceCleanup(dev, "kvm_assigned_device")
               && retries) {
            usleep(100*1000);
            retries--;
        }
        if (pciReAttachDevice(dev) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to re-attach PCI device: %s"),
                      err ? err->message : "");
            virResetError(err);
        }
    }
}

static void
qemuDomainReAttachHostDevices(struct qemud_driver *driver,
                              virDomainDefPtr def)
{
    pciDeviceList *pcidevs;
    int i;

    if (!def->nhostdevs)
        return;

    if (!(pcidevs = qemuGetPciHostDeviceList(def))) {
        virErrorPtr err = virGetLastError();
        VIR_ERROR(_("Failed to allocate pciDeviceList: %s"),
                  err ? err->message : "");
        virResetError(err);
        return;
    }

    /* Again 3 loops; mark all devices as inactive before reset
     * them and reset all the devices before re-attach */

    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        pciDeviceListDel(driver->activePciHostdevs, dev);
    }

    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        if (pciResetDevice(dev, driver->activePciHostdevs) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to reset PCI device: %s"),
                      err ? err->message : "");
            virResetError(err);
        }
    }

    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        qemudReattachManagedDevice(dev);
    }

    pciDeviceListFree(pcidevs);
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

static int qemuSetupCgroup(struct qemud_driver *driver,
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
        virReportSystemError(-rc,
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

            virReportSystemError(-rc,
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
                virReportSystemError(-rc,
                                     _("Unable to allow device %s for %s"),
                                     vm->def->disks[i]->src, vm->def->name);
                goto cleanup;
            }
        }

        rc = virCgroupAllowDeviceMajor(cgroup, 'c', DEVICE_PTY_MAJOR);
        if (rc != 0) {
            virReportSystemError(-rc, "%s",
                                 _("unable to allow /dev/pts/ devices"));
            goto cleanup;
        }

        if (vm->def->nsounds) {
            rc = virCgroupAllowDeviceMajor(cgroup, 'c', DEVICE_SND_MAJOR);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to allow /dev/snd/ devices"));
                goto cleanup;
            }
        }

        for (i = 0; deviceACL[i] != NULL ; i++) {
            rc = virCgroupAllowDevicePath(cgroup,
                                          deviceACL[i]);
            if (rc < 0 &&
                rc != -ENOENT) {
                virReportSystemError(-rc,
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


static int qemuRemoveCgroup(struct qemud_driver *driver,
                            virDomainObjPtr vm,
                            int quiet)
{
    virCgroupPtr cgroup;
    int rc;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0);
    if (rc != 0) {
        if (!quiet)
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportSystemError(-rc,
                             _("unable to find cgroup for domain %s"),
                             def->name);
        goto cleanup;
    }

    rc = virCgroupAddTask(cgroup, getpid());
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("unable to add domain %s task %d to cgroup"),
                             def->name, getpid());
        goto cleanup;
    }

    ret = 0;

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}


struct qemudHookData {
    virConnectPtr conn;
    virDomainObjPtr vm;
    struct qemud_driver *driver;
};

static int qemudSecurityHook(void *data) {
    struct qemudHookData *h = data;

    if (qemuAddToCgroup(h->driver, h->vm->def) < 0)
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
    monConfig->targetType = VIR_DOMAIN_CHR_TARGET_TYPE_MONITOR;

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
    unsigned long long qemuCmdFlags;
    fd_set keepfd;
    const char *emulator;
    pid_t child;
    int pos = -1;
    char ebuf[1024];
    char *pidfile = NULL;
    int logfile;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    struct qemudHookData hookData;
    hookData.conn = conn;
    hookData.vm = vm;
    hookData.driver = driver;

    FD_ZERO(&keepfd);

    if (virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("VM is already active"));
        return -1;
    }

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    if (driver->securityDriver &&
        driver->securityDriver->domainGenSecurityLabel &&
        driver->securityDriver->domainGenSecurityLabel(vm) < 0)
        return -1;

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityAllLabel &&
        driver->securityDriver->domainSetSecurityAllLabel(vm) < 0)
        goto cleanup;

    /* Ensure no historical cgroup for this VM is lieing around bogus settings */
    qemuRemoveCgroup(driver, vm, 1);

    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport) {
        int port = qemudNextFreeVNCPort(driver);
        if (port < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("Unable to find an unused VNC port"));
            goto cleanup;
        }
        vm->def->graphics[0]->data.vnc.port = port;
    }

    if (virFileMakePath(driver->logDir) != 0) {
        virReportSystemError(errno,
                             _("cannot create log directory %s"),
                             driver->logDir);
        goto cleanup;
    }

    if ((logfile = qemudLogFD(driver, vm->def->name)) < 0)
        goto cleanup;

    emulator = vm->def->emulator;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so its hard to feed back a useful error
     */
    if (stat(emulator, &sb) < 0) {
        virReportSystemError(errno,
                             _("Cannot find QEMU binary %s"),
                             emulator);
        goto cleanup;
    }

    if (qemudExtractVersionInfo(emulator,
                                NULL,
                                &qemuCmdFlags) < 0)
        goto cleanup;

    if (qemuSetupCgroup(driver, vm) < 0)
        goto cleanup;

    if (qemuPrepareHostDevices(driver, vm->def) < 0)
        goto cleanup;

    if (VIR_ALLOC(priv->monConfig) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (qemuPrepareMonitorChr(driver, priv->monConfig, vm->def->name) < 0)
        goto cleanup;

#if HAVE_YAJL
    if (qemuCmdFlags & QEMUD_CMD_FLAG_MONITOR_JSON)
        priv->monJSON = 1;
    else
#endif
        priv->monJSON = 0;

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

    vm->def->id = driver->nextvmid++;
    if (qemudBuildCommandLine(conn, driver, vm->def, priv->monConfig,
                              priv->monJSON, qemuCmdFlags, &argv, &progenv,
                              &tapfds, &ntapfds, migrateFrom) < 0)
        goto cleanup;

    tmp = progenv;
    while (*tmp) {
        if (safewrite(logfile, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(logfile, " ", 1) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    tmp = argv;
    while (*tmp) {
        if (safewrite(logfile, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(logfile, " ", 1) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s"),
                     virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    if (safewrite(logfile, "\n", 1) < 0)
        VIR_WARN(_("Unable to write argv to logfile: %s"),
                 virStrerror(errno, ebuf, sizeof ebuf));

    if ((pos = lseek(logfile, 0, SEEK_END)) < 0)
        VIR_WARN(_("Unable to seek to end of logfile: %s"),
                 virStrerror(errno, ebuf, sizeof ebuf));

    for (i = 0 ; i < ntapfds ; i++)
        FD_SET(tapfds[i], &keepfd);

    ret = virExecDaemonize(argv, progenv, &keepfd, &child,
                           stdin_fd, &logfile, &logfile,
                           VIR_EXEC_NONBLOCK | VIR_EXEC_CLEAR_CAPS,
                           qemudSecurityHook, &hookData,
                           pidfile);
    VIR_FREE(pidfile);

    /* wait for qemu process to to show up */
    if (ret == 0) {
        if (virFileReadPid(driver->stateDir, vm->def->name, &vm->pid)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (ret == -1) /* The VM failed to start */
        goto cleanup;

    if (qemudWaitForMonitor(driver, vm, pos) < 0)
        goto abort;

    if (qemuDetectVcpuPIDs(driver, vm) < 0)
        goto abort;

    if (qemudInitCpuAffinity(vm) < 0)
        goto abort;

    if (qemuInitPasswords(conn, driver, vm, qemuCmdFlags) < 0)
        goto abort;

    /* If we have -device, then addresses are assigned explicitly.
     * If not, then we have to detect dynamic ones here */
    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        if (qemuInitPCIAddresses(driver, vm) < 0)
            goto abort;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorSetBalloon(priv->mon, vm->def->memory) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto abort;
    }

    if (migrateFrom == NULL) {
        /* Allow the CPUS to start executing */
        if (qemuMonitorStartCPUs(priv->mon, conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("resume operation failed"));
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            goto abort;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);


    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto abort;

    return 0;

cleanup:
    /* We jump here if we failed to start the VM for any reason
     * XXX investigate if we can kill this block and safely call
     * qemudShutdownVMDaemon even though no PID is running */
    qemuDomainReAttachHostDevices(driver, vm->def);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityAllLabel)
        driver->securityDriver->domainRestoreSecurityAllLabel(vm);
    if (driver->securityDriver &&
        driver->securityDriver->domainReleaseSecurityLabel)
        driver->securityDriver->domainReleaseSecurityLabel(vm);
    qemuRemoveCgroup(driver, vm, 1);
    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport)
        vm->def->graphics[0]->data.vnc.port = -1;
    if (logfile != -1)
        close(logfile);
    vm->def->id = -1;
    return -1;

abort:
    /* We jump here if we failed to initialize the now running VM
     * killing it off and pretend we never started it */
    qemudShutdownVMDaemon(driver, vm);

    if (logfile != -1)
        close(logfile);

    return -1;
}


static void qemudShutdownVMDaemon(struct qemud_driver *driver,
                                  virDomainObjPtr vm) {
    int ret;
    int retries = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virErrorPtr orig_err;
    virDomainDefPtr def;
    int i;

    if (!virDomainObjIsActive(vm))
        return;

    VIR_DEBUG("Shutting down VM '%s'", vm->def->name);

    /* This method is routinely used in clean up paths. Disable error
     * reporting so we don't squash a legit error. */
    orig_err = virSaveLastError();

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

    if (virKillProcess(vm->pid, 0) == 0 &&
        virKillProcess(vm->pid, SIGTERM) < 0)
        virReportSystemError(errno,
                             _("Failed to send SIGTERM to %s (%d)"),
                             vm->def->name, vm->pid);

    if (priv->mon &&
        qemuMonitorClose(priv->mon) == 0) {
        virDomainObjUnref(vm);
        priv->mon = NULL;
    }

    if (priv->monConfig) {
        if (priv->monConfig->type == VIR_DOMAIN_CHR_TYPE_UNIX)
            unlink(priv->monConfig->data.nix.path);
        virDomainChrDefFree(priv->monConfig);
        priv->monConfig = NULL;
    }

    /* shut it off for sure */
    virKillProcess(vm->pid, SIGKILL);

    /* Reset Security Labels */
    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityAllLabel)
        driver->securityDriver->domainRestoreSecurityAllLabel(vm);
    if (driver->securityDriver &&
        driver->securityDriver->domainReleaseSecurityLabel)
        driver->securityDriver->domainReleaseSecurityLabel(vm);

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
            if (net->ifname)
                delMacvtap(net->ifname);
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

    close(fd);
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


static int qemudGetVersion(virConnectPtr conn, unsigned long *version) {
    struct qemud_driver *driver = conn->privateData;
    int ret = -1;

    qemuDriverLock(driver);
    if (qemudExtractVersion(driver) < 0)
        goto cleanup;

    *version = qemu_driver->qemuVersion;
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
                                      unsigned int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;

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
                                  def)))
        goto cleanup;

    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup; /* XXXX free the 'vm' we created ? */

    if (qemudStartVMDaemon(conn, driver, vm, NULL, -1) < 0) {
        if (qemuDomainObjEndJob(vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
        goto endjob;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

endjob:
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
    if (vm->state != VIR_DOMAIN_PAUSED) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorStopCPUs(priv->mon) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            goto endjob;
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        vm->state = VIR_DOMAIN_PAUSED;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
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
        qemuDomainObjPrivatePtr priv = vm->privateData;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorStartCPUs(priv->mon, dom->conn) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("resume operation failed"));
            goto endjob;
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        vm->state = VIR_DOMAIN_RUNNING;
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

    qemudShutdownVMDaemon(driver, vm);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    if (newmax < vm->def->memory) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("cannot set max memory lower than current memory"));
        goto cleanup;
    }

    /* There isn't any way to change this value for a running qemu guest */
    qemuReportError(VIR_ERR_NO_SUPPORT,
                    "%s", _("cannot set max memory of an active domain"));

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

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    if (newmem > vm->def->maxmem) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("cannot set memory higher than max memory"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

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

    info->maxMem = vm->def->maxmem;

    if (virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        if (!priv->jobActive) {
            if (qemuDomainObjBeginJob(vm) < 0)
                goto cleanup;

            qemuDomainObjEnterMonitor(vm);
            err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
            qemuDomainObjExitMonitor(vm);
            if (err < 0) {
                if (qemuDomainObjEndJob(vm) == 0)
                    vm = NULL;
                goto cleanup;
            }

            if (err == 0)
                /* Balloon not supported, so maxmem is always the allocation */
                info->memory = vm->def->maxmem;
            else
                info->memory = balloon;

            if (qemuDomainObjEndJob(vm) == 0) {
                vm = NULL;
                goto cleanup;
            }
        } else {
            info->memory = vm->def->memory;
        }
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
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000ull };
        struct timeval now;
        int rc;

        if (priv->jobCancel) {
            priv->jobCancel = 0;
            VIR_DEBUG0("Cancelling migration at client request");
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            rc = qemuMonitorMigrateCancel(priv->mon);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (rc < 0) {
                VIR_WARN0("Unable to cancel migration");
            }
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
        priv->jobInfo.timeElapsed =
            ((now.tv_sec * 1000ull) + (now.tv_usec / 1000)) -
            priv->jobStart;

        switch (status) {
        case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
            priv->jobInfo.type = VIR_DOMAIN_JOB_NONE;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Migration is not active"));
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
                            "%s", _("Migration unexpectedly failed"));
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
            priv->jobInfo.type = VIR_DOMAIN_JOB_CANCELLED;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Migration was cancelled by client"));
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

static int qemudDomainSaveFileOpHook(int fd, void *data) {
    struct fileOpHookData *hdata = data;
    int ret = 0;

    if (safewrite(fd, hdata->header, sizeof(*hdata->header)) != sizeof(*hdata->header)) {
        ret = errno;
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                         _("failed to write save header to '%s'"), hdata->path);
        goto endjob;
    }

    if (safewrite(fd, hdata->xml, hdata->header->xml_len) != hdata->header->xml_len) {
        ret = errno;
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                         _("failed to write xml to '%s'"), hdata->path);
        goto endjob;
    }
endjob:
    return ret;
}


static int qemudDomainSave(virDomainPtr dom,
                           const char *path)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    char *xml = NULL;
    struct qemud_save_header header;
    struct fileOpHookData hdata;
    int bypassSecurityDriver = 0;
    int ret = -1;
    int rc;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;

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
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Invalid save image format specified "
                                    "in configuration file"));
            goto cleanup;
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
    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    /* Pause */
    if (vm->state == VIR_DOMAIN_RUNNING) {
        header.was_running = 1;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorStopCPUs(priv->mon) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            goto endjob;
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        vm->state = VIR_DOMAIN_PAUSED;
    }

    /* Get XML for the domain */
    xml = virDomainDefFormat(vm->def, VIR_DOMAIN_XML_SECURE);
    if (!xml) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to get domain xml"));
        goto endjob;
    }
    header.xml_len = strlen(xml) + 1;

    /* Setup hook data needed by virFileOperation hook function */
    hdata.dom = dom;
    hdata.path = path;
    hdata.xml = xml;
    hdata.header = &header;

    /* Write header to file, followed by XML */

    /* First try creating the file as root */
    if ((rc = virFileOperation(path, O_CREAT|O_TRUNC|O_WRONLY,
                               S_IRUSR|S_IWUSR,
                               getuid(), getgid(),
                               qemudDomainSaveFileOpHook, &hdata,
                               0)) != 0) {

        /* If we failed as root, and the error was permission-denied
           (EACCES), assume it's on a network-connected share where
           root access is restricted (eg, root-squashed NFS). If the
           qemu user (driver->user) is non-root, just set a flag to
           bypass security driver shenanigans, and retry the operation
           after doing setuid to qemu user */

        if ((rc != EACCES) ||
            driver->user == getuid()) {
            virReportSystemError(rc, _("Failed to create domain save file '%s'"),
                                 path);
            goto endjob;
        }

#ifdef __linux__
        /* On Linux we can also verify the FS-type of the directory. */
        char *dirpath, *p;
        struct statfs st;
        int statfs_ret;

        if ((dirpath = strdup(path)) == NULL) {
            virReportOOMError();
            goto endjob;
        }

        do {
            // Try less and less of the path until we get to a
            // directory we can stat. Even if we don't have 'x'
            // permission on any directory in the path on the NFS
            // server (assuming it's NFS), we will be able to stat the
            // mount point, and that will properly tell us if the
            // fstype is NFS.

            if ((p = strrchr(dirpath, '/')) == NULL) {
                qemuReportError(VIR_ERR_INVALID_ARG,
                                _("Invalid relative path '%s' for domain save file"),
                                path);
                VIR_FREE(dirpath);
                goto endjob;
            }

            if (p == dirpath)
                *(p+1) = '\0';
            else
                *p = '\0';

            statfs_ret = statfs(dirpath, &st);

        } while ((statfs_ret == -1) && (p != dirpath));

        if (statfs_ret == -1) {
            virReportSystemError(errno,
                                 _("Failed to create domain save file '%s'"
                                   " statfs of all elements of path failed."),
                                 path);
            VIR_FREE(dirpath);
            goto endjob;
        }

        if (st.f_type != NFS_SUPER_MAGIC) {
            virReportSystemError(rc,
                                 _("Failed to create domain save file '%s'"
                                   " (fstype of '%s' is 0x%X"),
                                 path, dirpath, (unsigned int) st.f_type);
            VIR_FREE(dirpath);
            goto endjob;
        }
        VIR_FREE(dirpath);
#endif

        /* Retry creating the file as driver->user */

        if ((rc = virFileOperation(path, O_CREAT|O_TRUNC|O_WRONLY,
                                   S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP,
                                   driver->user, driver->group,
                                   qemudDomainSaveFileOpHook, &hdata,
                                   VIR_FILE_OP_AS_UID)) != 0) {
            virReportSystemError(rc, _("Error from child process creating '%s'"),
                                 path);
            goto endjob;
        }

        /* Since we had to setuid to create the file, and the fstype
           is NFS, we assume it's a root-squashing NFS share, and that
           the security driver stuff would have failed anyway */

        bypassSecurityDriver = 1;
    }


    if ((!bypassSecurityDriver) &&
        driver->securityDriver &&
        driver->securityDriver->domainSetSavedStateLabel &&
        driver->securityDriver->domainSetSavedStateLabel(vm, path) == -1)
        goto endjob;

    if (header.compressed == QEMUD_SAVE_FORMAT_RAW) {
        const char *args[] = { "cat", NULL };
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        rc = qemuMonitorMigrateToCommand(priv->mon, 1, args, path);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    } else {
        const char *prog = qemudSaveCompressionTypeToString(header.compressed);
        const char *args[] = {
            prog,
            "-c",
            NULL
        };
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        rc = qemuMonitorMigrateToCommand(priv->mon, 1, args, path);
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
        driver->securityDriver->domainRestoreSavedStateLabel(vm, path) == -1)
        goto endjob;

    ret = 0;

    /* Shut it down */
    qemudShutdownVMDaemon(driver, vm);
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
    if (ret != 0 && header.was_running) {
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        rc = qemuMonitorStartCPUs(priv->mon, dom->conn);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        if (rc < 0)
            VIR_WARN0("Unable to resume guest CPUs after save failure");
        else
            vm->state = VIR_DOMAIN_RUNNING;
    }

    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
            vm = NULL;

cleanup:
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
    int ret = -1, fd = -1;
    virDomainEventPtr event = NULL;
    const char *args[] = {
        "cat",
        NULL,
    };
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

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    /* Create an empty file with appropriate ownership.  */
    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("failed to create '%s'"), path);
        goto endjob;
    }

    if (close(fd) < 0) {
        virReportSystemError(errno,
                             _("unable to save file %s"),
                             path);
        goto endjob;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSavedStateLabel &&
        driver->securityDriver->domainSetSavedStateLabel(vm, path) == -1)
        goto endjob;

    /* Migrate will always stop the VM, so the resume condition is
       independent of whether the stop command is issued.  */
    resume = (vm->state == VIR_DOMAIN_RUNNING);

    /* Pause domain for non-live dump */
    if (!(flags & VIR_DUMP_LIVE) && vm->state == VIR_DOMAIN_RUNNING) {
        qemuDomainObjEnterMonitor(vm);
        if (qemuMonitorStopCPUs(priv->mon) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto endjob;
        }
        qemuDomainObjExitMonitor(vm);
        paused = 1;
    }

    qemuDomainObjEnterMonitor(vm);
    ret = qemuMonitorMigrateToCommand(priv->mon, 1, args, path);
    qemuDomainObjExitMonitor(vm);

    if (ret < 0)
        goto endjob;

    ret = qemuDomainWaitForMigrationComplete(driver, vm);

    if (ret < 0)
        goto endjob;

    paused = 1;

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSavedStateLabel &&
        driver->securityDriver->domainRestoreSavedStateLabel(vm, path) == -1)
        goto endjob;

endjob:
    if ((ret == 0) && (flags & VIR_DUMP_CRASH)) {
        qemudShutdownVMDaemon(driver, vm);
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    }

    /* Since the monitor is always attached to a pty for libvirt, it
       will support synchronous operations so we always get here after
       the migration is complete.  */
    else if (resume && paused) {
        qemuDomainObjEnterMonitor(vm);
        if (qemuMonitorStartCPUs(priv->mon, dom->conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("resuming after dump failed"));
        }
        qemuDomainObjExitMonitor(vm);
    }

    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;
    else if ((ret == 0) && (flags & VIR_DUMP_CRASH) && !vm->persistent) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
    }

cleanup:
    if (ret != 0)
        unlink(path);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    return ret;
}


static int qemudDomainHotplugVcpus(virDomainObjPtr vm, unsigned int nvcpus)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, rc;
    int ret = -1;

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
    return ret;

unsupported:
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot change vcpu count of this domain"));
    goto cleanup;
}


static int qemudDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char * type;
    int max;
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

    if (nvcpus > max) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("requested vcpus is greater than max allowable"
                          " vcpus for the domain: %d > %d"), nvcpus, max);
        goto endjob;
    }

    ret = qemudDomainHotplugVcpus(vm, nvcpus);

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!(type = virDomainVirtTypeToString(vm->def->virtType))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unknown virt type in domain definition '%d'"),
                        vm->def->virtType);
        goto cleanup;
    }

    ret = qemudGetMaxVCPUs(NULL, type);

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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!(type = virDomainVirtTypeToString(vm->def->virtType))) {
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
        if (driver->securityDriver && driver->securityDriver->domainGetSecurityProcessLabel) {
            if (driver->securityDriver->domainGetSecurityProcessLabel(vm, seclabel) == -1) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
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

static int qemudOpenAsUID(const char *path, uid_t uid, pid_t *child_pid) {
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
        close(pipefd[1]);
        pipefd[1] = -1;

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
        if (pipefd[0] != -1)
            close(pipefd[0]);
        if (pipefd[1] != -1)
            close(pipefd[1]);
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
    close(pipefd[0]);

    if (forkRet < 0) {
        exit_code = errno;
        virReportSystemError(errno,
                             _("failed in child after forking to read '%s'"),
                             path);
        goto child_cleanup;
    }

    if (setuid(uid) != 0) {
        exit_code = errno;
        virReportSystemError(errno,
                             _("cannot setuid(%d) to read '%s'"),
                             uid, path);
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
    if (fd != -1)
        close(fd);
    if (pipefd[1] != -1)
        close(pipefd[1]);
    _exit(exit_code);
}

/* TODO: check seclabel restore */
static int qemudDomainRestore(virConnectPtr conn,
                              const char *path) {
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int fd = -1;
    pid_t read_pid = -1;
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
        if ((driver->user == 0) || (getuid() != 0)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("cannot read domain image"));
            goto cleanup;
        }

        /* Opening as root failed, but qemu runs as a different user
           that might have better luck. Create a pipe, then fork a
           child process to run as the qemu user, which will hopefully
           have the necessary authority to read the file. */
        if ((fd = qemudOpenAsUID(path, driver->user, &read_pid)) < 0) {
            /* error already reported */
            goto cleanup;
        }
    }

    if (saferead(fd, &header, sizeof(header)) != sizeof(header)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to read qemu header"));
        goto cleanup;
    }

    if (memcmp(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic)) != 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("image magic is incorrect"));
        goto cleanup;
    }

    if (header.version > QEMUD_SAVE_VERSION) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("image version is not supported (%d > %d)"),
                        header.version, QEMUD_SAVE_VERSION);
        goto cleanup;
    }

    if (VIR_ALLOC_N(xml, header.xml_len) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (saferead(fd, xml, header.xml_len) != header.xml_len) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to read XML"));
        goto cleanup;
    }

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to parse XML"));
        goto cleanup;
    }

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def))) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to assign new VM"));
        goto cleanup;
    }
    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    if (header.version == 2) {
        const char *intermediate_argv[3] = { NULL, "-dc", NULL };
        const char *prog = qemudSaveCompressionTypeToString(header.compressed);
        if (prog == NULL) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("Invalid compressed save format %d"),
                            header.compressed);
            goto endjob;
        }

        if (header.compressed != QEMUD_SAVE_FORMAT_RAW) {
            intermediate_argv[0] = prog;
            intermediatefd = fd;
            fd = -1;
            if (virExec(intermediate_argv, NULL, NULL,
                        &intermediate_pid, intermediatefd, &fd, NULL, 0) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Failed to start decompression binary %s"),
                                intermediate_argv[0]);
                goto endjob;
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
    if (read_pid != -1) {
        int wait_ret;
        int status;
        /* reap the process that read the file */
        while (((wait_ret = waitpid(read_pid, &status, 0)) == -1)
               && (errno == EINTR)) {
            /* empty */
        }
        read_pid = -1;
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
        if (!vm->persistent) {
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains,
                                        vm);
            vm = NULL;
        }
        goto endjob;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);

    /* If it was running before, resume it now. */
    if (header.was_running) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorStartCPUs(priv->mon, conn) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("failed to resume domain"));
            qemuDomainObjExitMonitorWithDriver(driver,vm);
            goto endjob;
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        vm->state = VIR_DOMAIN_RUNNING;
        virDomainSaveStatus(driver->caps, driver->stateDir, vm);
    }
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    virDomainDefFree(def);
    VIR_FREE(xml);
    if (fd != -1)
        close(fd);
    if (read_pid != 0) {
        /* reap the process that read the file */
        while ((waitpid(read_pid, NULL, 0) == -1)
               && (errno == EINTR)) {
            /* empty */
        }
    }
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
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    /* Refresh current memory based on balloon info */
    if (virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        /* Don't delay if someone's using the monitor, just use
         * existing most recent data instead */
        if (!priv->jobActive) {
            if (qemuDomainObjBeginJob(vm) < 0)
                goto cleanup;

            qemuDomainObjEnterMonitor(vm);
            err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
            qemuDomainObjExitMonitor(vm);
            if (qemuDomainObjEndJob(vm) == 0) {
                vm = NULL;
                goto cleanup;
            }
            if (err < 0)
                goto cleanup;
            if (err > 0)
                vm->def->memory = balloon;
            /* err == 0 indicates no balloon support, so ignore it */
        }
    }

    ret = virDomainDefFormat((flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef ?
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
    const char *emulator;
    unsigned long long qemuCmdFlags;
    struct stat sb;
    const char **retargv = NULL;
    const char **retenv = NULL;
    const char **tmp;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
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
        virReportSystemError(errno,
                             _("Cannot find QEMU binary %s"),
                             emulator);
        goto cleanup;
    }

    if (qemudExtractVersionInfo(emulator,
                                NULL,
                                &qemuCmdFlags) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot determine QEMU argv syntax %s"),
                        emulator);
        goto cleanup;
    }

    if (qemuPrepareMonitorChr(driver, &monConfig, def->name) < 0)
        goto cleanup;

    if (qemudBuildCommandLine(conn, driver, def,
                              &monConfig, 0, qemuCmdFlags,
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

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        goto cleanup;
    }

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

    ret = qemudStartVMDaemon(dom->conn, driver, vm, NULL, -1);
    if (ret != -1)
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);

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

    if (qemudProbeMachineTypes(def->emulator, &machines, &nmachines) < 0) {
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
                                  def))) {
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


static int qemudDomainChangeEjectableMedia(struct qemud_driver *driver,
                                           virDomainObjPtr vm,
                                           virDomainDiskDefPtr disk)
{
    virDomainDiskDefPtr origdisk = NULL;
    int i;
    int ret;

    origdisk = NULL;
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->bus == disk->bus &&
            STREQ(vm->def->disks[i]->dst, disk->dst)) {
            origdisk = vm->def->disks[i];
            break;
        }
    }

    if (!origdisk) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No device with bus '%s' and target '%s'"),
                        virDomainDiskBusTypeToString(disk->bus),
                        disk->dst);
        return -1;
    }

    if (!origdisk->info.alias) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("missing disk device alias name for %s"), origdisk->dst);
        return -1;
    }

    if (origdisk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        origdisk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Removable media not supported for %s device"),
                        virDomainDiskDeviceTypeToString(disk->device));
        return -1;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(vm, disk) < 0)
        return -1;

    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (disk->src) {
        const char *format = NULL;
        if (disk->type != VIR_DOMAIN_DISK_TYPE_DIR) {
            if (disk->driverType)
                format = disk->driverType;
            else if (origdisk->driverType)
                format = origdisk->driverType;
        }
        ret = qemuMonitorChangeMedia(priv->mon,
                                     origdisk->info.alias,
                                     disk->src, format);
    } else {
        ret = qemuMonitorEjectMedia(priv->mon, origdisk->info.alias);
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (ret < 0)
        goto error;

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(vm, origdisk) < 0)
        VIR_WARN("Unable to restore security label on ejected image %s", origdisk->src);

    VIR_FREE(origdisk->src);
    origdisk->src = disk->src;
    disk->src = NULL;
    origdisk->type = disk->type;

    virDomainDiskDefFree(disk);

    return ret;

error:
    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(vm, disk) < 0)
        VIR_WARN("Unable to restore security label on new media %s", disk->src);
    return -1;
}


static int qemudDomainAttachPciDiskDevice(struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainDiskDefPtr disk,
                                          int qemuCmdFlags)
{
    int i, ret;
    const char* type = virDomainDiskBusTypeToString(disk->bus);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;
    char *drivestr = NULL;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s already exists"), disk->dst);
            return -1;
        }
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(vm, disk) < 0)
        return -1;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &disk->info) < 0)
            goto error;
        if (qemuAssignDeviceDiskAlias(disk, qemuCmdFlags) < 0)
            goto error;

        if (!(drivestr = qemuBuildDriveStr(disk, 0, qemuCmdFlags)))
            goto error;

        if (!(devstr = qemuBuildDriveDevStr(disk)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError();
        goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        ret = qemuMonitorAddDrive(priv->mon, drivestr);
        if (ret == 0)
            qemuMonitorAddDevice(priv->mon, devstr);
            /* XXX remove the drive upon fail */
    } else {
        virDomainDevicePCIAddress guestAddr;
        ret = qemuMonitorAddPCIDisk(priv->mon,
                                    disk->src,
                                    type,
                                    &guestAddr);
        if (ret == 0) {
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            memcpy(&disk->info.addr.pci, &guestAddr, sizeof(guestAddr));
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    return 0;

error:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &disk->info) < 0)
        VIR_WARN("Unable to release PCI address on %s", disk->src);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(vm, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    return -1;
}


static int qemudDomainAttachPciControllerDevice(struct qemud_driver *driver,
                                                virDomainObjPtr vm,
                                                virDomainControllerDefPtr controller,
                                                int qemuCmdFlags)
{
    int i;
    int ret = -1;
    const char* type = virDomainControllerTypeToString(controller->type);
    char *devstr = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        if ((vm->def->controllers[i]->type == controller->type) &&
            (vm->def->controllers[i]->idx == controller->idx)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s:%d already exists"),
                            type, controller->idx);
            return -1;
        }
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &controller->info) < 0)
            goto cleanup;
        if (qemuAssignDeviceControllerAlias(controller) < 0)
            goto cleanup;
    }

    if (!(devstr = qemuBuildControllerDevStr(controller))) {
        virReportOOMError();
        goto cleanup;
    }

    if (VIR_REALLOC_N(vm->def->controllers, vm->def->ncontrollers+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    } else {
        ret = qemuMonitorAttachPCIDiskController(priv->mon,
                                                 type,
                                                 &controller->info.addr.pci);
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (ret == 0) {
        controller->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        virDomainControllerInsertPreAlloced(vm->def, controller);
    }

cleanup:
    if ((ret != 0) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &controller->info) < 0)
        VIR_WARN0("Unable to release PCI address on controller");

    VIR_FREE(devstr);
    return ret;
}


static virDomainControllerDefPtr
qemuDomainFindOrCreateSCSIDiskController(struct qemud_driver *driver,
                                         virDomainObjPtr vm,
                                         int controller,
                                         int qemuCmdFlags)
{
    int i;
    virDomainControllerDefPtr cont;
    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        cont = vm->def->controllers[i];

        if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            continue;

        if (cont->idx == controller)
            return cont;
    }

    /* No SCSI controller present, for backward compatibility we
     * now hotplug a controller */
    if (VIR_ALLOC(cont) < 0) {
        virReportOOMError();
        return NULL;
    }
    cont->type = VIR_DOMAIN_CONTROLLER_TYPE_SCSI;
    cont->idx = 0;

    VIR_INFO0("No SCSI controller present, hotplugging one");
    if (qemudDomainAttachPciControllerDevice(driver,
                                             vm, cont, qemuCmdFlags) < 0) {
        VIR_FREE(cont);
        return NULL;
    }
    return cont;
}


static int qemudDomainAttachSCSIDisk(struct qemud_driver *driver,
                                     virDomainObjPtr vm,
                                     virDomainDiskDefPtr disk,
                                     int qemuCmdFlags)
{
    int i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainControllerDefPtr cont;
    char *drivestr = NULL;
    char *devstr = NULL;
    int ret = -1;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s already exists"), disk->dst);
            return -1;
        }
    }


    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(vm, disk) < 0)
        return -1;

    /* We should have an address already, so make sure */
    if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unexpected disk address type %s"),
                        virDomainDeviceAddressTypeToString(disk->info.type));
        goto error;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceDiskAlias(disk, qemuCmdFlags) < 0)
            goto error;
        if (!(devstr = qemuBuildDriveDevStr(disk)))
            goto error;
    }

    if (!(drivestr = qemuBuildDriveStr(disk, 0, qemuCmdFlags)))
        goto error;

    for (i = 0 ; i <= disk->info.addr.drive.controller ; i++) {
        cont = qemuDomainFindOrCreateSCSIDiskController(driver, vm, i, qemuCmdFlags);
        if (!cont)
            goto error;
    }

    if (cont->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("SCSI controller %d was missing its PCI address"), cont->idx);
        goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError();
        goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        ret = qemuMonitorAddDrive(priv->mon,
                                  drivestr);
        if (ret == 0)
            ret = qemuMonitorAddDevice(priv->mon,
                                       devstr);
            /* XXX should call 'drive_del' on error but this does not exist yet */
    } else {
        virDomainDeviceDriveAddress driveAddr;
        ret = qemuMonitorAttachDrive(priv->mon,
                                     drivestr,
                                     &cont->info.addr.pci,
                                     &driveAddr);
        if (ret == 0) {
            /* XXX we should probably validate that the addr matches
             * our existing defined addr instead of overwriting */
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
            memcpy(&disk->info.addr.drive, &driveAddr, sizeof(driveAddr));
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    return 0;

error:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(vm, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    return -1;
}


static int qemudDomainAttachUsbMassstorageDevice(struct qemud_driver *driver,
                                                 virDomainObjPtr vm,
                                                 virDomainDiskDefPtr disk,
                                                 int qemuCmdFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, ret;
    char *drivestr = NULL;
    char *devstr = NULL;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s already exists"), disk->dst);
            return -1;
        }
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(vm, disk) < 0)
        return -1;

    if (!disk->src) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("disk source path is missing"));
        goto error;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceDiskAlias(disk, qemuCmdFlags) < 0)
            goto error;
        if (!(drivestr = qemuBuildDriveStr(disk, 0, qemuCmdFlags)))
            goto error;
        if (!(devstr = qemuBuildDriveDevStr(disk)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError();
        goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        ret = qemuMonitorAddDrive(priv->mon,
                                  drivestr);
        if (ret == 0)
            ret = qemuMonitorAddDevice(priv->mon,
                                       devstr);
            /* XXX should call 'drive_del' on error but this does not exist yet */
    } else {
        ret = qemuMonitorAddUSBDisk(priv->mon, disk->src);
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    return 0;

error:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(vm, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    return -1;
}


/* XXX conn required for network -> bridge resolution */
static int qemudDomainAttachNetDevice(virConnectPtr conn,
                                      struct qemud_driver *driver,
                                      virDomainObjPtr vm,
                                      virDomainNetDefPtr net,
                                      unsigned long long qemuCmdFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *tapfd_name = NULL;
    int tapfd = -1;
    char *nicstr = NULL;
    char *netstr = NULL;
    int ret = -1;
    virDomainDevicePCIAddress guestAddr;
    int vlan;

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_HOST_NET_ADD)) {
        qemuReportError(VIR_ERR_NO_SUPPORT, "%s",
                        _("installed qemu version does not support host_net_add"));
        return -1;
    }

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (priv->monConfig->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
            qemuReportError(VIR_ERR_NO_SUPPORT,
                            _("network device type '%s' cannot be attached: "
                              "qemu is not using a unix socket monitor"),
                            virDomainNetTypeToString(net->type));
            return -1;
        }

        if ((tapfd = qemudNetworkIfaceConnect(conn, driver, net, qemuCmdFlags)) < 0)
            return -1;
    } else if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
        if (priv->monConfig->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
            qemuReportError(VIR_ERR_NO_SUPPORT,
                            _("network device type '%s' cannot be attached: "
                            "qemu is not using a unix socket monitor"),
                            virDomainNetTypeToString(net->type));
            return -1;
        }

        if ((tapfd = qemudPhysIfaceConnect(conn, driver, net,
                                           net->data.direct.linkdev,
                                           net->data.direct.mode,
                                           qemuCmdFlags)) < 0)
            return -1;
    }

    if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets+1) < 0)
        goto no_memory;

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NET_NAME) ||
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        if (qemuAssignDeviceNetAlias(vm->def, net, -1) < 0)
            goto cleanup;
    }

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &net->info) < 0)
        goto cleanup;

    vlan = qemuDomainNetVLAN(net);

    if (vlan < 0) {
        qemuReportError(VIR_ERR_NO_SUPPORT, "%s",
                        _("Unable to attach network devices without vlan"));
        goto cleanup;
    }

    if (tapfd != -1) {
        if (virAsprintf(&tapfd_name, "fd-%s", net->info.alias) < 0)
            goto no_memory;

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorSendFileHandle(priv->mon, tapfd_name, tapfd) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            goto cleanup;
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

    if (!(netstr = qemuBuildHostNetStr(net, ' ',
                                       vlan, tapfd_name)))
        goto try_tapfd_close;

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorAddHostNetwork(priv->mon, netstr) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto try_tapfd_close;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (tapfd != -1)
        close(tapfd);
    tapfd = -1;

    if (!(nicstr = qemuBuildNicStr(net, NULL, vlan)))
        goto try_remove;

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorAddPCINetwork(priv->mon, nicstr,
                                 &guestAddr) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto try_remove;
    }
    net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    memcpy(&net->info.addr.pci, &guestAddr, sizeof(guestAddr));
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    ret = 0;

    vm->def->nets[vm->def->nnets++] = net;

cleanup:
    if ((ret != 0) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &net->info) < 0)
        VIR_WARN0("Unable to release PCI address on NIC");

    VIR_FREE(nicstr);
    VIR_FREE(netstr);
    VIR_FREE(tapfd_name);
    if (tapfd != -1)
        close(tapfd);

    return ret;

try_remove:
    if (vlan < 0) {
        VIR_WARN0(_("Unable to remove network backend"));
    } else {
        char *hostnet_name;
        if (virAsprintf(&hostnet_name, "host%s", net->info.alias) < 0)
            goto no_memory;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorRemoveHostNetwork(priv->mon, vlan, hostnet_name) < 0)
            VIR_WARN(_("Failed to remove network backend for vlan %d, net %s"),
                     vlan, hostnet_name);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        VIR_FREE(hostnet_name);
    }
    goto cleanup;

try_tapfd_close:
    if (tapfd_name) {
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorCloseFileHandle(priv->mon, tapfd_name) < 0)
            VIR_WARN(_("Failed to close tapfd with '%s'"), tapfd_name);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

    goto cleanup;

no_memory:
    virReportOOMError();
    goto cleanup;
}


static int qemudDomainAttachHostPciDevice(struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainHostdevDefPtr hostdev,
                                          int qemuCmdFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    pciDevice *pci;
    int ret;
    virDomainDevicePCIAddress guestAddr;
    char *devstr = NULL;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        virReportOOMError();
        return -1;
    }

    pci = pciGetDevice(hostdev->source.subsys.u.pci.domain,
                       hostdev->source.subsys.u.pci.bus,
                       hostdev->source.subsys.u.pci.slot,
                       hostdev->source.subsys.u.pci.function);
    if (!pci)
        return -1;

    if (!pciDeviceIsAssignable(pci, !driver->relaxedACS) ||
        (hostdev->managed && pciDettachDevice(pci) < 0) ||
        pciResetDevice(pci, driver->activePciHostdevs) < 0) {
        pciFreeDevice(pci);
        return -1;
    }

    if (pciDeviceListAdd(driver->activePciHostdevs, pci) < 0) {
        pciFreeDevice(pci);
        return -1;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
            goto error;
        if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &hostdev->info) < 0)
            goto error;

        if (!(devstr = qemuBuildPCIHostdevDevStr(hostdev)))
            goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    else
        ret = qemuMonitorAddPCIHostDevice(priv->mon,
                                          &hostdev->source.subsys.u.pci,
                                          &guestAddr);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (ret < 0)
        goto error;
    hostdev->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    memcpy(&hostdev->info.addr.pci, &guestAddr, sizeof(guestAddr));

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    VIR_FREE(devstr);

    return 0;

error:
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (hostdev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &hostdev->info) < 0)
        VIR_WARN0("Unable to release PCI address on host device");

    VIR_FREE(devstr);
    pciDeviceListDel(driver->activePciHostdevs, pci);

    return -1;
}


static int qemudDomainAttachHostUsbDevice(struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainHostdevDefPtr hostdev,
                                          int qemuCmdFlags)
{
    int ret;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
            goto error;
        if (!(devstr = qemuBuildUSBHostdevDevStr(hostdev)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        virReportOOMError();
        goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    else
        ret = qemuMonitorAddUSBDeviceExact(priv->mon,
                                           hostdev->source.subsys.u.usb.bus,
                                           hostdev->source.subsys.u.usb.device);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (ret < 0)
        goto error;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    VIR_FREE(devstr);

    return 0;

error:
    VIR_FREE(devstr);
    return -1;
}


static int qemudDomainAttachHostDevice(struct qemud_driver *driver,
                                       virDomainObjPtr vm,
                                       virDomainHostdevDefPtr hostdev,
                                       int qemuCmdFlags)
{
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        _("hostdev mode '%s' not supported"),
                        virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    /* Resolve USB product/vendor to bus/device */
    if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
        hostdev->source.subsys.u.usb.vendor) {
        usbDevice *usb
            = usbFindDevice(hostdev->source.subsys.u.usb.vendor,
                            hostdev->source.subsys.u.usb.product);

        if (!usb)
            return -1;

        hostdev->source.subsys.u.usb.bus = usbDeviceGetBus(usb);
        hostdev->source.subsys.u.usb.device = usbDeviceGetDevno(usb);

        usbFreeDevice(usb);
    }


    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityHostdevLabel &&
        driver->securityDriver->domainSetSecurityHostdevLabel(vm, hostdev) < 0)
        return -1;

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (qemudDomainAttachHostPciDevice(driver, vm,
                                           hostdev, qemuCmdFlags) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (qemudDomainAttachHostUsbDevice(driver, vm,
                                           hostdev, qemuCmdFlags) < 0)
            goto error;
        break;

    default:
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        _("hostdev subsys type '%s' not supported"),
                        virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        goto error;
    }

    return 0;

error:
    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel(vm, hostdev) < 0)
        VIR_WARN0("Unable to restore host device labelling on hotplug fail");

    return -1;
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

    if (qemudExtractVersionInfo(vm->def->emulator,
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
            if (dev->data.disk->src != NULL &&
                dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK &&
                virCgroupAllowDevicePath(cgroup,
                                         dev->data.disk->src) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("unable to allow device %s"),
                                dev->data.disk->src);
                goto endjob;
            }
        }

        switch (dev->data.disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            ret = qemudDomainChangeEjectableMedia(driver, vm, dev->data.disk);
            if (ret == 0)
                dev->data.disk = NULL;
            break;

        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                ret = qemudDomainAttachUsbMassstorageDevice(driver, vm,
                                                            dev->data.disk, qemuCmdFlags);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
                ret = qemudDomainAttachPciDiskDevice(driver, vm,
                                                     dev->data.disk, qemuCmdFlags);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
                ret = qemudDomainAttachSCSIDisk(driver, vm,
                                                dev->data.disk, qemuCmdFlags);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else {
                qemuReportError(VIR_ERR_NO_SUPPORT,
                                _("disk bus '%s' cannot be hotplugged."),
                                virDomainDiskBusTypeToString(dev->data.disk->bus));
                /* fallthrough */
            }
            break;

        default:
            qemuReportError(VIR_ERR_NO_SUPPORT,
                            _("disk device type '%s' cannot be hotplugged"),
                            virDomainDiskDeviceTypeToString(dev->data.disk->device));
            /* Fallthrough */
        }
        if (ret != 0 && cgroup) {
            virCgroupDenyDevicePath(cgroup,
                                    dev->data.disk->src);
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        if (dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            ret = qemudDomainAttachPciControllerDevice(driver, vm,
                                                       dev->data.controller, qemuCmdFlags);
            if (ret == 0)
                dev->data.controller = NULL;
        } else {
            qemuReportError(VIR_ERR_NO_SUPPORT,
                            _("disk controller bus '%s' cannot be hotplugged."),
                            virDomainControllerTypeToString(dev->data.controller->type));
            /* fallthrough */
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        ret = qemudDomainAttachNetDevice(dom->conn, driver, vm,
                                         dev->data.net, qemuCmdFlags);
        if (ret == 0)
            dev->data.net = NULL;
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemudDomainAttachHostDevice(driver, vm,
                                          dev->data.hostdev, qemuCmdFlags);
        if (ret == 0)
            dev->data.hostdev = NULL;
    } else {
        qemuReportError(VIR_ERR_NO_SUPPORT,
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

static int qemudDomainDetachPciDiskDevice(struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev,
                                          unsigned long long qemuCmdFlags)
{
    int i, ret = -1;
    virDomainDiskDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            detach = vm->def->disks[i];
            break;
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("disk %s not found"), dev->data.disk->dst);
        goto cleanup;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("device cannot be detached without a PCI address"));
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

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

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(vm, dev->data.disk) < 0)
        VIR_WARN("Unable to restore security label on %s", dev->data.disk->src);

    ret = 0;

cleanup:
    return ret;
}

static int qemudDomainDetachPciControllerDevice(struct qemud_driver *driver,
                                                virDomainObjPtr vm,
                                                virDomainDeviceDefPtr dev,
                                                unsigned long long qemuCmdFlags)
{
    int i, ret = -1;
    virDomainControllerDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        if ((vm->def->controllers[i]->type == dev->data.controller->type) &&
            (vm->def->controllers[i]->idx == dev->data.controller->idx)) {
            detach = vm->def->controllers[i];
            break;
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("disk controller %s:%d not found"),
                        virDomainControllerTypeToString(dev->data.controller->type),
                        dev->data.controller->idx);
        goto cleanup;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("device cannot be detached without a PCI address"));
        goto cleanup;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceControllerAlias(detach) < 0)
            goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias)) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (vm->def->ncontrollers > 1) {
        memmove(vm->def->controllers + i,
                vm->def->controllers + i + 1,
                sizeof(*vm->def->controllers) *
                (vm->def->ncontrollers - (i + 1)));
        vm->def->ncontrollers--;
        if (VIR_REALLOC_N(vm->def->controllers, vm->def->ncontrollers) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->controllers);
        vm->def->ncontrollers = 0;
    }

    if (qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &detach->info) < 0) {
        VIR_WARN0("Unable to release PCI address on controller");
    }

    virDomainControllerDefFree(detach);

    ret = 0;

cleanup:
    return ret;
}

static int
qemudDomainDetachNetDevice(struct qemud_driver *driver,
                           virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev,
                           unsigned long long qemuCmdFlags)
{
    int i, ret = -1;
    virDomainNetDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int vlan;
    char *hostnet_name = NULL;

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];

        if (!memcmp(net->mac, dev->data.net->mac,  sizeof(net->mac))) {
            detach = net;
            break;
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("network device %02x:%02x:%02x:%02x:%02x:%02x not found"),
                        dev->data.net->mac[0], dev->data.net->mac[1],
                        dev->data.net->mac[2], dev->data.net->mac[3],
                        dev->data.net->mac[4], dev->data.net->mac[5]);
        goto cleanup;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached without a PCI address"));
        goto cleanup;
    }

    if ((vlan = qemuDomainNetVLAN(detach)) < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("unable to determine original VLAN"));
        goto cleanup;
    }

    if (virAsprintf(&hostnet_name, "host%s", detach->info.alias) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            goto cleanup;
        }
    }

    if (qemuMonitorRemoveHostNetwork(priv->mon, vlan, hostnet_name) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cleanup;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

#if WITH_MACVTAP
    if (detach->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
        if (detach->ifname)
            delMacvtap(detach->ifname);
    }
#endif

    if ((driver->macFilter) && (detach->ifname != NULL)) {
        if ((errno = networkDisallowMacOnPort(driver,
                                              detach->ifname,
                                              detach->mac))) {
            virReportSystemError(errno,
             _("failed to remove ebtables rule on  '%s'"),
                                 detach->ifname);
        }
    }

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
    VIR_FREE(hostnet_name);
    return ret;
}

static int qemudDomainDetachHostPciDevice(struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev,
                                          unsigned long long qemuCmdFlags)
{
    virDomainHostdevDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, ret;
    pciDevice *pci;

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (vm->def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            vm->def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

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
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("host pci device %.4x:%.2x:%.2x.%.1x not found"),
                        dev->data.hostdev->source.subsys.u.pci.domain,
                        dev->data.hostdev->source.subsys.u.pci.bus,
                        dev->data.hostdev->source.subsys.u.pci.slot,
                        dev->data.hostdev->source.subsys.u.pci.function);
        return -1;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached without a PCI address"));
        return -1;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(vm);
            return -1;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            return -1;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    ret = 0;

    pci = pciGetDevice(detach->source.subsys.u.pci.domain,
                       detach->source.subsys.u.pci.bus,
                       detach->source.subsys.u.pci.slot,
                       detach->source.subsys.u.pci.function);
    if (!pci)
        ret = -1;
    else {
        pciDeviceSetManaged(pci, detach->managed);
        pciDeviceListDel(driver->activePciHostdevs, pci);
        if (pciResetDevice(pci, driver->activePciHostdevs) < 0)
            ret = -1;
        qemudReattachManagedDevice(pci);
        pciFreeDevice(pci);
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

static int qemudDomainDetachHostUsbDevice(struct qemud_driver *driver,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev,
                                          unsigned long long qemuCmdFlags)
{
    virDomainHostdevDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, ret;

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (vm->def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            vm->def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        unsigned bus = vm->def->hostdevs[i]->source.subsys.u.usb.bus;
        unsigned device = vm->def->hostdevs[i]->source.subsys.u.usb.device;
        unsigned product = vm->def->hostdevs[i]->source.subsys.u.usb.product;
        unsigned vendor = vm->def->hostdevs[i]->source.subsys.u.usb.vendor;

        if (dev->data.hostdev->source.subsys.u.usb.bus &&
            dev->data.hostdev->source.subsys.u.usb.device) {
            if (dev->data.hostdev->source.subsys.u.usb.bus == bus &&
                dev->data.hostdev->source.subsys.u.usb.device == device) {
                detach = vm->def->hostdevs[i];
                break;
            }
        } else {
            if (dev->data.hostdev->source.subsys.u.usb.product == product &&
                dev->data.hostdev->source.subsys.u.usb.vendor == vendor) {
                detach = vm->def->hostdevs[i];
                break;
            }
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("host usb device %03d.%03d not found"),
                        dev->data.hostdev->source.subsys.u.usb.bus,
                        dev->data.hostdev->source.subsys.u.usb.device);
        return -1;
    }

    if (!detach->info.alias) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached without a device alias"));
        return -1;
    }

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached with this QEMU version"));
        return -1;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        return -1;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    ret = 0;

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

static int qemudDomainDetachHostDevice(struct qemud_driver *driver,
                                       virDomainObjPtr vm,
                                       virDomainDeviceDefPtr dev,
                                       unsigned long long qemuCmdFlags)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;
    int ret;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        _("hostdev mode '%s' not supported"),
                        virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        ret = qemudDomainDetachHostPciDevice(driver, vm, dev, qemuCmdFlags);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        ret = qemudDomainDetachHostUsbDevice(driver, vm, dev, qemuCmdFlags);
        break;
    default:
        qemuReportError(VIR_ERR_NO_SUPPORT,
                        _("hostdev subsys type '%s' not supported"),
                        virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        return -1;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel(vm, dev->data.hostdev) < 0)
        VIR_WARN0("Failed to restore host device labelling");

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

    if (qemudExtractVersionInfo(vm->def->emulator,
                                NULL,
                                &qemuCmdFlags) < 0)
        goto endjob;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
        ret = qemudDomainDetachPciDiskDevice(driver, vm, dev, qemuCmdFlags);
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        ret = qemudDomainDetachNetDevice(driver, vm, dev, qemuCmdFlags);
    } else if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        if (dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            ret = qemudDomainDetachPciControllerDevice(driver, vm, dev,
                                                       qemuCmdFlags);
        } else {
            qemuReportError(VIR_ERR_NO_SUPPORT,
                            _("disk controller bus '%s' cannot be hotunplugged."),
                            virDomainControllerTypeToString(dev->data.controller->type));
            /* fallthrough */
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemudDomainDetachHostDevice(driver, vm, dev, qemuCmdFlags);
    } else {
        qemuReportError(VIR_ERR_NO_SUPPORT,
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

    if (virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        qemuDomainObjEnterMonitor(vm);
        ret = qemuMonitorTextGetMemoryStats(priv->mon, stats, nr_stats);
        qemuDomainObjExitMonitor(vm);
    } else {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
    }

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

    if (virAsprintf(&tmp, driver->cacheDir,  "/qemu.mem.XXXXXX") < 0) {
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
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("stream is not open"));
        return -1;
    }

    qemuDriverLock(driver);
    if (qemust->watch == 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("stream is not open"));
        return -1;
    }

    qemuDriverLock(driver);
    if (qemust->watch == 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("stream is not open"));
        return -1;
    }

    qemuDriverLock(driver);
    if (qemust->watch != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("stream already has a callback registered"));
        goto cleanup;
    }

    if ((qemust->watch = virEventAddHandle(qemust->fd,
                                           events,
                                           qemuStreamMigEvent,
                                           st,
                                           NULL)) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (VIR_ALLOC(qemust) < 0) {
        virReportOOMError();
        return NULL;
    }

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
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
            virReportSystemError(errno, "%s",
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
    unsigned long long qemuCmdFlags;
    struct qemuStreamMigFile *qemust = NULL;

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
                                  def))) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to assign new VM"));
        goto cleanup;
    }
    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (virAsprintf(&unixfile, "%s/qemu.tunnelmigrate.dest.%s",
                    driver->stateDir, vm->def->name) < 0) {
        virReportOOMError();
        goto endjob;
    }
    unlink(unixfile);

    /* check that this qemu version supports the interactive exec */
    if (qemudExtractVersionInfo(vm->def->emulator, NULL, &qemuCmdFlags) < 0) {
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
        goto endjob;
    }

    qemust = qemuStreamMigOpen(st, unixfile);
    if (qemust == NULL) {
        qemudShutdownVMDaemon(driver, vm);
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

    st->driver = &qemuStreamMigDrv;
    st->privateData = qemust;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
        if ((hostname = virGetHostnameLocalhost(0)) == NULL)
            goto cleanup;

        /* XXX this really should have been a properly well-formed
         * URI, but we can't add in tcp:// now without breaking
         * compatability with old targets. We at least make the
         * new targets accept both syntaxes though.
         */
        /* Caller frees */
        internalret = virAsprintf(uri_out, "tcp:%s:%d", hostname, this_port);
        VIR_FREE(hostname);
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
                                  def))) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to assign new VM"));
        goto cleanup;
    }
    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

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
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        goto endjob;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

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
static int doNativeMigrate(struct qemud_driver *driver,
                           virDomainObjPtr vm,
                           const char *uri,
                           unsigned long flags ATTRIBUTE_UNUSED,
                           const char *dname ATTRIBUTE_UNUSED,
                           unsigned long resource)
{
    int ret = -1;
    xmlURIPtr uribits = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

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

    if (qemuMonitorMigrateToHost(priv->mon, 1, uribits->server, uribits->port) < 0) {
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


static int doTunnelSendAll(virStreamPtr st,
                           int sock)
{
    char buffer[65536];
    int nbytes = sizeof(buffer);

    /* XXX should honour the 'resource' parameter here */
    for (;;) {
        nbytes = saferead(sock, buffer, nbytes);
        if (nbytes < 0) {
            virStreamAbort(st);
            virReportSystemError(errno, "%s",
                                 _("tunnelled migration failed to read from qemu"));
            return -1;
        }
        else if (nbytes == 0)
            /* EOF; get out of here */
            break;

        if (virStreamSend(st, buffer, nbytes) < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
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

    /* check that this qemu version supports the unix migration */
    if (qemudExtractVersionInfo(vm->def->emulator, NULL, &qemuCmdFlags) < 0) {
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

    internalret = dconn->driver->domainMigratePrepareTunnel(dconn, st,
                                                            flags, dname,
                                                            resource, dom_xml);

    if (internalret < 0)
        /* domainMigratePrepareTunnel sets the error for us */
        goto cleanup;

    /*   3. start migration on source */
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX)
        internalret = qemuMonitorMigrateToUnix(priv->mon, 1, unixfile);
    else if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC) {
        const char *args[] = { "nc", "-U", unixfile, NULL };
        internalret = qemuMonitorMigrateToCommand(priv->mon, 1, args, "/dev/null");
    } else {
        internalret = -1;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (internalret < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("tunnelled migration monitor command failed"));
        goto finish;
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
    if (retval != 0) {
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        qemuMonitorMigrateCancel(priv->mon);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

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
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("domainMigratePrepare2 did not set uri"));
        goto cleanup;
    }

    if (doNativeMigrate(driver, vm, uri_out, flags, dname, resource) < 0)
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

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    dconn = virConnectOpen(uri);
    if (dconn == NULL) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("Failed to connect to remote libvirt URI %s"), uri);
        return -1;
    }
    if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                  VIR_DRV_FEATURE_MIGRATION_P2P)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    dom_xml = virDomainDefFormat(vm->def, VIR_DOMAIN_XML_SECURE);
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
    int paused = 0;
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

    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    if (!(flags & VIR_MIGRATE_LIVE) && vm->state == VIR_DOMAIN_RUNNING) {
        /* Pause domain for non-live migration */
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorStopCPUs(priv->mon) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            goto endjob;
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        paused = 1;

        vm->state = VIR_DOMAIN_PAUSED;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
        if (event)
            qemuDomainEventQueue(driver, event);
        event = NULL;
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
    qemudShutdownVMDaemon(driver, vm);
    paused = 0;

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
    if (paused) {
        /* we got here through some sort of failure; start the domain again */
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorStartCPUs(priv->mon, dom->conn) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best
             */
            VIR_ERROR(_("Failed to resume guest %s after failure"),
                      vm->def->name);
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);

        vm->state = VIR_DOMAIN_RUNNING;
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

    /* Migration failed. Save the current error so nothing squashes it */
    orig_err = virSaveLastError();

    qemuDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dname);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching name '%s'"), dname);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    /* Did the migration go as planned?  If yes, return the domain
     * object, but if no, clean up the empty qemu process.
     */
    if (retcode == 0) {
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
        qemuDomainObjPrivatePtr priv = vm->privateData;
        dom = virGetDomain (dconn, vm->def->name, vm->def->uuid);

        if (!(flags & VIR_MIGRATE_PAUSED)) {
            /* run 'cont' on the destination, which allows migration on qemu
             * >= 0.10.6 to work properly.  This isn't strictly necessary on
             * older qemu's, but it also doesn't hurt anything there
             */
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            if (qemuMonitorStartCPUs(priv->mon, dconn) < 0) {
                if (virGetLastError() == NULL)
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("resume operation failed"));
                qemuDomainObjExitMonitorWithDriver(driver, vm);
                goto endjob;
            }
            qemuDomainObjExitMonitorWithDriver(driver, vm);

            vm->state = VIR_DOMAIN_RUNNING;
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
        virDomainSaveStatus(driver->caps, driver->stateDir, vm);
    } else {
        qemudShutdownVMDaemon(driver, vm);
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
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (qemudNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciDettachDevice(pci) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(pci);
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

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciReAttachDevice(pci) < 0)
        goto out;

    ret = 0;
out:
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

    if (pciResetDevice(pci, driver->activePciHostdevs) < 0)
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
            memcpy(info, &priv->jobInfo, sizeof(*info));
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
            priv->jobCancel = 1;
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
    qemudDomainSetMaxMemory, /* domainSetMaxMemory */
    qemudDomainSetMemory, /* domainSetMemory */
    qemudDomainGetInfo, /* domainGetInfo */
    qemudDomainSave, /* domainSave */
    qemudDomainRestore, /* domainRestore */
    qemudDomainCoreDump, /* domainCoreDump */
    qemudDomainSetVcpus, /* domainSetVcpus */
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
    qemudDomainDefine, /* domainDefineXML */
    qemudDomainUndefine, /* domainUndefine */
    qemudDomainAttachDevice, /* domainAttachDevice */
    qemudDomainAttachDeviceFlags, /* domainAttachDeviceFlags */
    qemudDomainDetachDevice, /* domainDetachDevice */
    qemudDomainDetachDeviceFlags, /* domainDetachDeviceFlags */
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
    qemuIsEncrypted,
    qemuIsSecure,
    qemuDomainIsActive,
    qemuDomainIsPersistent,
    qemuCPUCompare, /* cpuCompare */
    qemuCPUBaseline, /* cpuBaseline */
    qemuDomainGetJobInfo, /* domainGetJobInfo */
    qemuDomainAbortJob, /* domainAbortJob */
};


static virStateDriver qemuStateDriver = {
    .name = "QEMU",
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
