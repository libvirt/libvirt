/*
 * qemu_driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <paths.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <byteswap.h>


#include "qemu_driver.h"
#include "qemu_agent.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_command.h"
#include "qemu_cgroup.h"
#include "qemu_hostdev.h"
#include "qemu_hotplug.h"
#include "qemu_monitor.h"
#include "qemu_process.h"
#include "qemu_migration.h"
#include "qemu_blockjob.h"

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "nodeinfo.h"
#include "virstats.h"
#include "capabilities.h"
#include "viralloc.h"
#include "viruuid.h"
#include "domain_conf.h"
#include "domain_audit.h"
#include "node_device_conf.h"
#include "virpci.h"
#include "virusb.h"
#include "virprocess.h"
#include "libvirt_internal.h"
#include "virxml.h"
#include "cpu/cpu.h"
#include "virsysinfo.h"
#include "domain_nwfilter.h"
#include "nwfilter_conf.h"
#include "virhook.h"
#include "virstoragefile.h"
#include "virfile.h"
#include "fdstream.h"
#include "configmake.h"
#include "virthreadpool.h"
#include "locking/lock_manager.h"
#include "locking/domain_lock.h"
#include "virkeycode.h"
#include "virnodesuspend.h"
#include "virtime.h"
#include "virtypedparam.h"
#include "virbitmap.h"
#include "virstring.h"
#include "viraccessapicheck.h"
#include "viraccessapicheckqemu.h"
#include "storage/storage_driver.h"
#include "virhostdev.h"
#include "domain_capabilities.h"
#include "vircgroup.h"
#include "virnuma.h"
#include "dirname.h"
#include "network/bridge_driver.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_driver");

#define QEMU_NB_MEM_PARAM  3

#define QEMU_NB_BLOCK_IO_TUNE_PARAM  6
#define QEMU_NB_BLOCK_IO_TUNE_PARAM_MAX  13

#define QEMU_NB_NUMA_PARAM 2

#define QEMU_SCHED_MIN_PERIOD              1000LL
#define QEMU_SCHED_MAX_PERIOD           1000000LL
#define QEMU_SCHED_MIN_QUOTA               1000LL
#define QEMU_SCHED_MAX_QUOTA  18446744073709551LL

#if HAVE_LINUX_KVM_H
# include <linux/kvm.h>
#endif

/* device for kvm ioctls */
#define KVM_DEVICE "/dev/kvm"

/* add definitions missing in older linux/kvm.h */
#ifndef KVMIO
# define KVMIO 0xAE
#endif
#ifndef KVM_CHECK_EXTENSION
# define KVM_CHECK_EXTENSION       _IO(KVMIO,   0x03)
#endif
#ifndef KVM_CAP_NR_VCPUS
# define KVM_CAP_NR_VCPUS 9       /* returns max vcpus per vm */
#endif

#define QEMU_NB_BLKIO_PARAM  6

#define QEMU_NB_BANDWIDTH_PARAM 7

static void processWatchdogEvent(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 int action);

static void processGuestPanicEvent(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   int action);

static void qemuProcessEventHandler(void *data, void *opaque);

static int qemuStateCleanup(void);

static int qemuDomainObjStart(virConnectPtr conn,
                              virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              unsigned int flags,
                              qemuDomainAsyncJob asyncJob);

static int qemuDomainGetMaxVcpus(virDomainPtr dom);

static int qemuDomainManagedSaveLoad(virDomainObjPtr vm,
                                     void *opaque);

static int qemuOpenFile(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        const char *path, int oflags,
                        bool *needUnlink, bool *bypassSecurityDriver);

static int qemuOpenFileAs(uid_t fallback_uid, gid_t fallback_gid,
                          bool dynamicOwnership,
                          const char *path, int oflags,
                          bool *needUnlink, bool *bypassSecurityDriver);

static int qemuGetDHCPInterfaces(virDomainPtr dom,
                                 virDomainObjPtr vm,
                                 virDomainInterfacePtr **ifaces);

virQEMUDriverPtr qemu_driver = NULL;


static void
qemuVMDriverLock(void)
{}
static void
qemuVMDriverUnlock(void)
{}

static int
qemuVMFilterRebuild(virDomainObjListIterator iter, void *data)
{
    return virDomainObjListForEach(qemu_driver->domains, iter, data);
}

static virNWFilterCallbackDriver qemuCallbackDriver = {
    .name = QEMU_DRIVER_NAME,
    .vmFilterRebuild = qemuVMFilterRebuild,
    .vmDriverLock = qemuVMDriverLock,
    .vmDriverUnlock = qemuVMDriverUnlock,
};


struct qemuAutostartData {
    virQEMUDriverPtr driver;
    virConnectPtr conn;
};


/**
 * qemuDomObjFromDomain:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate virDomainObjPtr
 * that has to be released by calling virDomainObjEndAPI().
 *
 * Returns the domain object with incremented reference counter which is locked
 * on success, NULL otherwise.
 */
static virDomainObjPtr
qemuDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    virQEMUDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUIDRef(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

/* Looks up the domain object from snapshot and unlocks the
 * driver. The returned domain object is locked and ref'd and the
 * caller must call virDomainObjEndAPI() on it. */
static virDomainObjPtr
qemuDomObjFromSnapshot(virDomainSnapshotPtr snapshot)
{
    return qemuDomObjFromDomain(snapshot->domain);
}


/* Looks up snapshot object from VM and name */
static virDomainSnapshotObjPtr
qemuSnapObjFromName(virDomainObjPtr vm,
                    const char *name)
{
    virDomainSnapshotObjPtr snap = NULL;
    snap = virDomainSnapshotFindByName(vm->snapshots, name);
    if (!snap)
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("no domain snapshot with matching name '%s'"),
                       name);

    return snap;
}


/* Looks up snapshot object from VM and snapshotPtr */
static virDomainSnapshotObjPtr
qemuSnapObjFromSnapshot(virDomainObjPtr vm,
                        virDomainSnapshotPtr snapshot)
{
    return qemuSnapObjFromName(vm, snapshot->name);
}

static int
qemuAutostartDomain(virDomainObjPtr vm,
                    void *opaque)
{
    struct qemuAutostartData *data = opaque;
    virErrorPtr err;
    int flags = 0;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(data->driver);
    int ret = -1;

    if (cfg->autoStartBypassCache)
        flags |= VIR_DOMAIN_START_BYPASS_CACHE;

    virObjectLock(vm);
    virObjectRef(vm);
    virResetLastError();
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        if (qemuProcessBeginJob(data->driver, vm) < 0) {
            err = virGetLastError();
            VIR_ERROR(_("Failed to start job on VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : _("unknown error"));
            goto cleanup;
        }

        if (qemuDomainObjStart(data->conn, data->driver, vm, flags,
                               QEMU_ASYNC_JOB_START) < 0) {
            err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : _("unknown error"));
        }

        qemuProcessEndJob(data->driver, vm);
    }

    ret = 0;
 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


static void
qemuAutostartDomains(virQEMUDriverPtr driver)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen(cfg->uri);
    /* Ignoring NULL conn which is mostly harmless here */
    struct qemuAutostartData data = { driver, conn };

    virDomainObjListForEach(driver->domains, qemuAutostartDomain, &data);

    virObjectUnref(conn);
    virObjectUnref(cfg);
}


static int
qemuSecurityChownCallback(virStorageSourcePtr src,
                          uid_t uid,
                          gid_t gid)
{
    struct stat sb;
    int save_errno = 0;
    int ret = -1;

    if (!virStorageFileSupportsSecurityDriver(src))
        return 0;

    if (virStorageSourceIsLocalStorage(src)) {
        /* use direct chmod for local files so that the file doesn't
         * need to be initialized */
        if (!src->path)
            return 0;

        if (stat(src->path, &sb) >= 0) {
            if (sb.st_uid == uid &&
                sb.st_gid == gid) {
                /* It's alright, there's nothing to change anyway. */
                return 0;
            }
        }

        return chown(src->path, uid, gid);
    }

    /* storage file init reports errors, return -2 on failure */
    if (virStorageFileInit(src) < 0)
        return -2;

    if (virStorageFileChown(src, uid, gid) < 0) {
        save_errno = errno;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStorageFileDeinit(src);
    errno = save_errno;

    return ret;
}


static int
qemuSecurityInit(virQEMUDriverPtr driver)
{
    char **names;
    virSecurityManagerPtr mgr = NULL;
    virSecurityManagerPtr stack = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    unsigned int flags = 0;

    if (cfg->allowDiskFormatProbing)
        flags |= VIR_SECURITY_MANAGER_ALLOW_DISK_PROBE;
    if (cfg->securityDefaultConfined)
        flags |= VIR_SECURITY_MANAGER_DEFAULT_CONFINED;
    if (cfg->securityRequireConfined)
        flags |= VIR_SECURITY_MANAGER_REQUIRE_CONFINED;
    if (virQEMUDriverIsPrivileged(driver))
        flags |= VIR_SECURITY_MANAGER_PRIVILEGED;

    if (cfg->securityDriverNames &&
        cfg->securityDriverNames[0]) {
        names = cfg->securityDriverNames;
        while (names && *names) {
            if (!(mgr = virSecurityManagerNew(*names,
                                              QEMU_DRIVER_NAME,
                                              flags)))
                goto error;
            if (!stack) {
                if (!(stack = virSecurityManagerNewStack(mgr)))
                    goto error;
            } else {
                if (virSecurityManagerStackAddNested(stack, mgr) < 0)
                    goto error;
            }
            mgr = NULL;
            names++;
        }
    } else {
        if (!(mgr = virSecurityManagerNew(NULL,
                                          QEMU_DRIVER_NAME,
                                          flags)))
            goto error;
        if (!(stack = virSecurityManagerNewStack(mgr)))
            goto error;
        mgr = NULL;
    }

    if (virQEMUDriverIsPrivileged(driver)) {
        if (cfg->dynamicOwnership)
            flags |= VIR_SECURITY_MANAGER_DYNAMIC_OWNERSHIP;
        if (!(mgr = virSecurityManagerNewDAC(QEMU_DRIVER_NAME,
                                             cfg->user,
                                             cfg->group,
                                             flags,
                                             qemuSecurityChownCallback)))
            goto error;
        if (!stack) {
            if (!(stack = virSecurityManagerNewStack(mgr)))
                goto error;
        } else {
            if (virSecurityManagerStackAddNested(stack, mgr) < 0)
                goto error;
        }
        mgr = NULL;
    }

    driver->securityManager = stack;
    virObjectUnref(cfg);
    return 0;

 error:
    VIR_ERROR(_("Failed to initialize security drivers"));
    virObjectUnref(stack);
    virObjectUnref(mgr);
    virObjectUnref(cfg);
    return -1;
}


static int
qemuDomainSnapshotLoad(virDomainObjPtr vm,
                       void *data)
{
    char *baseDir = (char *)data;
    char *snapDir = NULL;
    DIR *dir = NULL;
    struct dirent *entry;
    char *xmlStr;
    char *fullpath;
    virDomainSnapshotDefPtr def = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotObjPtr current = NULL;
    char ebuf[1024];
    unsigned int flags = (VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE |
                          VIR_DOMAIN_SNAPSHOT_PARSE_DISKS |
                          VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL);
    int ret = -1;
    virCapsPtr caps = NULL;
    int direrr;

    virObjectLock(vm);
    if (virAsprintf(&snapDir, "%s/%s", baseDir, vm->def->name) < 0) {
        VIR_ERROR(_("Failed to allocate memory for snapshot directory for domain %s"),
                   vm->def->name);
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(qemu_driver, false)))
        goto cleanup;

    VIR_INFO("Scanning for snapshots for domain %s in %s", vm->def->name,
             snapDir);

    if (!(dir = opendir(snapDir))) {
        if (errno != ENOENT)
            VIR_ERROR(_("Failed to open snapshot directory %s for domain %s: %s"),
                      snapDir, vm->def->name,
                      virStrerror(errno, ebuf, sizeof(ebuf)));
        goto cleanup;
    }

    while ((direrr = virDirRead(dir, &entry, NULL)) > 0) {
        if (entry->d_name[0] == '.')
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        VIR_INFO("Loading snapshot file '%s'", entry->d_name);

        if (virAsprintf(&fullpath, "%s/%s", snapDir, entry->d_name) < 0) {
            VIR_ERROR(_("Failed to allocate memory for path"));
            continue;
        }

        if (virFileReadAll(fullpath, 1024*1024*1, &xmlStr) < 0) {
            /* Nothing we can do here, skip this one */
            VIR_ERROR(_("Failed to read snapshot file %s: %s"), fullpath,
                      virStrerror(errno, ebuf, sizeof(ebuf)));
            VIR_FREE(fullpath);
            continue;
        }

        def = virDomainSnapshotDefParseString(xmlStr, caps,
                                              qemu_driver->xmlopt,
                                              flags);
        if (def == NULL) {
            /* Nothing we can do here, skip this one */
            VIR_ERROR(_("Failed to parse snapshot XML from file '%s'"),
                      fullpath);
            VIR_FREE(fullpath);
            VIR_FREE(xmlStr);
            continue;
        }

        snap = virDomainSnapshotAssignDef(vm->snapshots, def);
        if (snap == NULL) {
            virDomainSnapshotDefFree(def);
        } else if (snap->def->current) {
            current = snap;
            if (!vm->current_snapshot)
                vm->current_snapshot = snap;
        }

        VIR_FREE(fullpath);
        VIR_FREE(xmlStr);
    }
    if (direrr < 0)
        VIR_ERROR(_("Failed to fully read directory %s"), snapDir);

    if (vm->current_snapshot != current) {
        VIR_ERROR(_("Too many snapshots claiming to be current for domain %s"),
                  vm->def->name);
        vm->current_snapshot = NULL;
    }

    if (virDomainSnapshotUpdateRelations(vm->snapshots) < 0)
        VIR_ERROR(_("Snapshots have inconsistent relations for domain %s"),
                  vm->def->name);

    /* FIXME: qemu keeps internal track of snapshots.  We can get access
     * to this info via the "info snapshots" monitor command for running
     * domains, or via "qemu-img snapshot -l" for shutoff domains.  It would
     * be nice to update our internal state based on that, but there is a
     * a problem.  qemu doesn't track all of the same metadata that we do.
     * In particular we wouldn't be able to fill in the <parent>, which is
     * pretty important in our metadata.
     */

    virResetLastError();

    ret = 0;
 cleanup:
    if (dir)
        closedir(dir);
    VIR_FREE(snapDir);
    virObjectUnref(caps);
    virObjectUnlock(vm);
    return ret;
}


static int
qemuDomainNetsRestart(virDomainObjPtr vm,
                      void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    virDomainDefPtr def = vm->def;

    virObjectLock(vm);

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT &&
            virDomainNetGetActualDirectMode(net) == VIR_NETDEV_MACVLAN_MODE_VEPA) {
            VIR_DEBUG("VEPA mode device %s active in domain %s. Reassociating.",
                      net->ifname, def->name);
            ignore_value(virNetDevMacVLanRestartWithVPortProfile(net->ifname,
                                                                 &net->mac,
                                                                 virDomainNetGetActualDirectDev(net),
                                                                 def->uuid,
                                                                 virDomainNetGetActualVirtPortProfile(net),
                                                                 VIR_NETDEV_VPORT_PROFILE_OP_CREATE));
        }
    }

    virObjectUnlock(vm);
    return 0;
}


static int
qemuDomainFindMaxID(virDomainObjPtr vm,
                    void *data)
{
    int *driver_maxid = data;

    if (vm->def->id > *driver_maxid)
        *driver_maxid = vm->def->id;

    return 0;
}


/**
 * qemuStateInitialize:
 *
 * Initialization function for the QEmu daemon
 */
static int
qemuStateInitialize(bool privileged,
                    virStateInhibitCallback callback,
                    void *opaque)
{
    char *driverConf = NULL;
    virConnectPtr conn = NULL;
    char ebuf[1024];
    virQEMUDriverConfigPtr cfg;
    uid_t run_uid = -1;
    gid_t run_gid = -1;
    char *hugepagePath = NULL;
    size_t i;

    if (VIR_ALLOC(qemu_driver) < 0)
        return -1;

    if (virMutexInit(&qemu_driver->lock) < 0) {
        VIR_ERROR(_("cannot initialize mutex"));
        VIR_FREE(qemu_driver);
        return -1;
    }

    qemu_driver->inhibitCallback = callback;
    qemu_driver->inhibitOpaque = opaque;

    qemu_driver->privileged = privileged;

    if (!(qemu_driver->domains = virDomainObjListNew()))
        goto error;

    /* Init domain events */
    qemu_driver->domainEventState = virObjectEventStateNew();
    if (!qemu_driver->domainEventState)
        goto error;

    /* read the host sysinfo */
    if (privileged)
        qemu_driver->hostsysinfo = virSysinfoRead();

    if (!(qemu_driver->config = cfg = virQEMUDriverConfigNew(privileged)))
        goto error;

    if (virAsprintf(&driverConf, "%s/qemu.conf", cfg->configBaseDir) < 0)
        goto error;

    if (virQEMUDriverConfigLoadFile(cfg, driverConf) < 0)
        goto error;
    VIR_FREE(driverConf);

    if (virFileMakePath(cfg->stateDir) < 0) {
        VIR_ERROR(_("Failed to create state dir '%s': %s"),
                  cfg->stateDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->libDir) < 0) {
        VIR_ERROR(_("Failed to create lib dir '%s': %s"),
                  cfg->libDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->cacheDir) < 0) {
        VIR_ERROR(_("Failed to create cache dir '%s': %s"),
                  cfg->cacheDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->saveDir) < 0) {
        VIR_ERROR(_("Failed to create save dir '%s': %s"),
                  cfg->saveDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->snapshotDir) < 0) {
        VIR_ERROR(_("Failed to create save dir '%s': %s"),
                  cfg->snapshotDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->autoDumpPath) < 0) {
        VIR_ERROR(_("Failed to create dump dir '%s': %s"),
                  cfg->autoDumpPath, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->channelTargetDir) < 0) {
        VIR_ERROR(_("Failed to create channel target dir '%s': %s"),
                  cfg->channelTargetDir,
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->nvramDir) < 0) {
        VIR_ERROR(_("Failed to create nvram dir '%s': %s"),
                  cfg->nvramDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }

    qemu_driver->qemuImgBinary = virFindFileInPath("kvm-img");
    if (!qemu_driver->qemuImgBinary)
        qemu_driver->qemuImgBinary = virFindFileInPath("qemu-img");

    if (!(qemu_driver->lockManager =
          virLockManagerPluginNew(cfg->lockManagerName ?
                                  cfg->lockManagerName : "nop",
                                  "qemu",
                                  cfg->configBaseDir,
                                  0)))
        goto error;

   if (cfg->macFilter) {
        if (!(qemu_driver->ebtables = ebtablesContextNew("qemu"))) {
            virReportSystemError(errno,
                                 _("failed to enable mac filter in '%s'"),
                                 __FILE__);
            goto error;
        }

        if (ebtablesAddForwardPolicyReject(qemu_driver->ebtables) < 0)
            goto error;
   }

    /* Allocate bitmap for remote display port reservations. We cannot
     * do this before the config is loaded properly, since the port
     * numbers are configurable now */
    if ((qemu_driver->remotePorts =
         virPortAllocatorNew(_("display"),
                             cfg->remotePortMin,
                             cfg->remotePortMax,
                             0)) == NULL)
        goto error;

    if ((qemu_driver->webSocketPorts =
         virPortAllocatorNew(_("webSocket"),
                             cfg->webSocketPortMin,
                             cfg->webSocketPortMax,
                             0)) == NULL)
        goto error;

    if ((qemu_driver->migrationPorts =
         virPortAllocatorNew(_("migration"),
                             cfg->migrationPortMin,
                             cfg->migrationPortMax,
                             0)) == NULL)
        goto error;

    if (qemuSecurityInit(qemu_driver) < 0)
        goto error;

    if (!(qemu_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto error;

    if (!(qemu_driver->sharedDevices = virHashCreate(30, qemuSharedDeviceEntryFree)))
        goto error;

    if (qemuMigrationErrorInit(qemu_driver) < 0)
        goto error;

    if (privileged) {
        char *channeldir;

        if (chown(cfg->libDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to user %d:%d"),
                                 cfg->libDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }
        if (chown(cfg->cacheDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 cfg->cacheDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }
        if (chown(cfg->saveDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 cfg->saveDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }
        if (chown(cfg->snapshotDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 cfg->snapshotDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }
        if (chown(cfg->autoDumpPath, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 cfg->autoDumpPath, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }
        if (!(channeldir = mdir_name(cfg->channelTargetDir))) {
            virReportOOMError();
            goto error;
        }
        if (chown(channeldir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 channeldir, (int) cfg->user,
                                 (int) cfg->group);
            VIR_FREE(channeldir);
            goto error;
        }
        VIR_FREE(channeldir);
        if (chown(cfg->channelTargetDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 cfg->channelTargetDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }
        if (chown(cfg->nvramDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _("unable to set ownership of '%s' to %d:%d"),
                                 cfg->nvramDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }

        run_uid = cfg->user;
        run_gid = cfg->group;
    }

    qemu_driver->qemuCapsCache = virQEMUCapsCacheNew(cfg->libDir,
                                                     cfg->cacheDir,
                                                     run_uid,
                                                     run_gid);
    if (!qemu_driver->qemuCapsCache)
        goto error;

    if ((qemu_driver->caps = virQEMUDriverCreateCapabilities(qemu_driver)) == NULL)
        goto error;

    if (!(qemu_driver->xmlopt = virQEMUDriverCreateXMLConf(qemu_driver)))
        goto error;

    /* If hugetlbfs is present, then we need to create a sub-directory within
     * it, since we can't assume the root mount point has permissions that
     * will let our spawned QEMU instances use it. */
    for (i = 0; i < cfg->nhugetlbfs; i++) {
        hugepagePath = qemuGetHugepagePath(&cfg->hugetlbfs[i]);

        if (!hugepagePath)
            goto error;

        if (virFileMakePath(hugepagePath) < 0) {
            virReportSystemError(errno,
                                 _("unable to create hugepage path %s"),
                                 hugepagePath);
            goto error;
        }
        if (privileged) {
            if (virFileUpdatePerm(cfg->hugetlbfs[i].mnt_dir,
                                  0, S_IXGRP | S_IXOTH) < 0)
                goto error;
            if (chown(hugepagePath, cfg->user, cfg->group) < 0) {
                virReportSystemError(errno,
                                     _("unable to set ownership on %s to %d:%d"),
                                     hugepagePath,
                                     (int) cfg->user,
                                     (int) cfg->group);
                goto error;
            }
        }
        VIR_FREE(hugepagePath);
    }

    if (!(qemu_driver->closeCallbacks = virCloseCallbacksNew()))
        goto error;

    /* Get all the running persistent or transient configs first */
    if (virDomainObjListLoadAllConfigs(qemu_driver->domains,
                                       cfg->stateDir,
                                       NULL, 1,
                                       qemu_driver->caps,
                                       qemu_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto error;

    /* find the maximum ID from active and transient configs to initialize
     * the driver with. This is to avoid race between autostart and reconnect
     * threads */
    virDomainObjListForEach(qemu_driver->domains,
                            qemuDomainFindMaxID,
                            &qemu_driver->lastvmid);

    virDomainObjListForEach(qemu_driver->domains,
                            qemuDomainNetsRestart,
                            NULL);

    conn = virConnectOpen(cfg->uri);

    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(qemu_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir, 0,
                                       qemu_driver->caps,
                                       qemu_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto error;

    virDomainObjListForEach(qemu_driver->domains,
                            qemuDomainSnapshotLoad,
                            cfg->snapshotDir);

    virDomainObjListForEach(qemu_driver->domains,
                            qemuDomainManagedSaveLoad,
                            qemu_driver);

    qemuProcessReconnectAll(conn, qemu_driver);

    qemu_driver->workerPool = virThreadPoolNew(0, 1, 0, qemuProcessEventHandler, qemu_driver);
    if (!qemu_driver->workerPool)
        goto error;

    virObjectUnref(conn);

    virNWFilterRegisterCallbackDriver(&qemuCallbackDriver);
    return 0;

 error:
    virObjectUnref(conn);
    VIR_FREE(driverConf);
    VIR_FREE(hugepagePath);
    qemuStateCleanup();
    return -1;
}

/**
 * qemuStateAutoStart:
 *
 * Function to auto start the QEmu daemons
 */
static void
qemuStateAutoStart(void)
{
    if (!qemu_driver)
        return;

    qemuAutostartDomains(qemu_driver);
}

static void qemuNotifyLoadDomain(virDomainObjPtr vm, int newVM, void *opaque)
{
    virQEMUDriverPtr driver = opaque;

    if (newVM) {
        virObjectEventPtr event =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
        qemuDomainEventQueue(driver, event);
    }
}

/**
 * qemuStateReload:
 *
 * Function to restart the QEmu daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
qemuStateReload(void)
{
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    if (!qemu_driver)
        return 0;

    if (!(caps = virQEMUDriverGetCapabilities(qemu_driver, false)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(qemu_driver);
    virDomainObjListLoadAllConfigs(qemu_driver->domains,
                                   cfg->configDir,
                                   cfg->autostartDir, 0,
                                   caps, qemu_driver->xmlopt,
                                   qemuNotifyLoadDomain, qemu_driver);
 cleanup:
    virObjectUnref(cfg);
    virObjectUnref(caps);
    return 0;
}


/*
 * qemuStateStop:
 *
 * Save any VMs in preparation for shutdown
 *
 */
static int
qemuStateStop(void)
{
    int ret = -1;
    virConnectPtr conn;
    int numDomains = 0;
    size_t i;
    int state;
    virDomainPtr *domains = NULL;
    unsigned int *flags = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(qemu_driver);

    if (!(conn = virConnectOpen(cfg->uri)))
        goto cleanup;

    if ((numDomains = virConnectListAllDomains(conn,
                                               &domains,
                                               VIR_CONNECT_LIST_DOMAINS_ACTIVE)) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(flags, numDomains) < 0)
        goto cleanup;

    /* First we pause all VMs to make them stop dirtying
       pages, etc. We remember if any VMs were paused so
       we can restore that on resume. */
    for (i = 0; i < numDomains; i++) {
        flags[i] = VIR_DOMAIN_SAVE_RUNNING;
        if (virDomainGetState(domains[i], &state, NULL, 0) == 0) {
            if (state == VIR_DOMAIN_PAUSED)
                flags[i] = VIR_DOMAIN_SAVE_PAUSED;
        }
        virDomainSuspend(domains[i]);
    }

    ret = 0;
    /* Then we save the VMs to disk */
    for (i = 0; i < numDomains; i++)
        if (virDomainManagedSave(domains[i], flags[i]) < 0)
            ret = -1;

 cleanup:
    if (domains) {
        for (i = 0; i < numDomains; i++)
            virObjectUnref(domains[i]);
        VIR_FREE(domains);
    }
    VIR_FREE(flags);
    virObjectUnref(conn);
    virObjectUnref(cfg);

    return ret;
}

/**
 * qemuStateCleanup:
 *
 * Shutdown the QEmu daemon, it will stop all active domains and networks
 */
static int
qemuStateCleanup(void)
{
    if (!qemu_driver)
        return -1;

    virNWFilterUnRegisterCallbackDriver(&qemuCallbackDriver);
    virObjectUnref(qemu_driver->config);
    virObjectUnref(qemu_driver->hostdevMgr);
    virHashFree(qemu_driver->sharedDevices);
    virObjectUnref(qemu_driver->caps);
    virQEMUCapsCacheFree(qemu_driver->qemuCapsCache);

    virObjectUnref(qemu_driver->domains);
    virObjectUnref(qemu_driver->remotePorts);
    virObjectUnref(qemu_driver->webSocketPorts);
    virObjectUnref(qemu_driver->migrationPorts);
    virObjectUnref(qemu_driver->migrationErrors);

    virObjectUnref(qemu_driver->xmlopt);

    virSysinfoDefFree(qemu_driver->hostsysinfo);

    virObjectUnref(qemu_driver->closeCallbacks);

    VIR_FREE(qemu_driver->qemuImgBinary);

    virObjectUnref(qemu_driver->securityManager);

    ebtablesContextFree(qemu_driver->ebtables);

    /* Free domain callback list */
    virObjectEventStateFree(qemu_driver->domainEventState);

    virLockManagerPluginUnref(qemu_driver->lockManager);

    virMutexDestroy(&qemu_driver->lock);
    virThreadPoolFree(qemu_driver->workerPool);
    VIR_FREE(qemu_driver);

    return 0;
}


static virDrvOpenStatus qemuConnectOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                        unsigned int flags)
{
    virQEMUDriverConfigPtr cfg = NULL;
    virDrvOpenStatus ret = VIR_DRV_OPEN_ERROR;
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL) {
        if (qemu_driver == NULL) {
            ret = VIR_DRV_OPEN_DECLINED;
            goto cleanup;
        }

        cfg = virQEMUDriverGetConfig(qemu_driver);

        if (!(conn->uri = virURIParse(cfg->uri)))
            goto cleanup;
    } else {
        /* If URI isn't 'qemu' its definitely not for us */
        if (conn->uri->scheme == NULL ||
            STRNEQ(conn->uri->scheme, "qemu")) {
            ret = VIR_DRV_OPEN_DECLINED;
            goto cleanup;
        }

        /* Allow remote driver to deal with URIs with hostname server */
        if (conn->uri->server != NULL) {
            ret = VIR_DRV_OPEN_DECLINED;
            goto cleanup;
        }

        if (qemu_driver == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu state driver is not active"));
            goto cleanup;
        }

        cfg = virQEMUDriverGetConfig(qemu_driver);
        if (conn->uri->path == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("no QEMU URI path given, try %s"),
                           cfg->uri);
            goto cleanup;
        }

        if (virQEMUDriverIsPrivileged(qemu_driver)) {
            if (STRNEQ(conn->uri->path, "/system") &&
                STRNEQ(conn->uri->path, "/session")) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected QEMU URI path '%s', try qemu:///system"),
                               conn->uri->path);
                goto cleanup;
            }
        } else {
            if (STRNEQ(conn->uri->path, "/session")) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected QEMU URI path '%s', try qemu:///session"),
                               conn->uri->path);
                goto cleanup;
            }
        }
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        goto cleanup;

    conn->privateData = qemu_driver;

    ret = VIR_DRV_OPEN_SUCCESS;
 cleanup:
    virObjectUnref(cfg);
    return ret;
}

static int qemuConnectClose(virConnectPtr conn)
{
    virQEMUDriverPtr driver = conn->privateData;

    /* Get rid of callbacks registered for this conn */
    virCloseCallbacksRun(driver->closeCallbacks, conn, driver->domains, driver);

    conn->privateData = NULL;

    return 0;
}

/* Which features are supported by this driver? */
static int
qemuConnectSupportsFeature(virConnectPtr conn, int feature)
{
    if (virConnectSupportsFeatureEnsureACL(conn) < 0)
        return -1;

    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_MIGRATION_V3:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
    case VIR_DRV_FEATURE_FD_PASSING:
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
    case VIR_DRV_FEATURE_XML_MIGRATABLE:
    case VIR_DRV_FEATURE_MIGRATION_OFFLINE:
    case VIR_DRV_FEATURE_MIGRATION_PARAMS:
        return 1;
    default:
        return 0;
    }
}

static const char *qemuConnectGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "QEMU";
}


static int qemuConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}

static int qemuConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}

static int qemuConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}


static int
kvmGetMaxVCPUs(void)
{
    int fd;
    int ret;

    if ((fd = open(KVM_DEVICE, O_RDONLY)) < 0) {
        virReportSystemError(errno, _("Unable to open %s"), KVM_DEVICE);
        return -1;
    }

#ifdef KVM_CAP_MAX_VCPUS
    /* at first try KVM_CAP_MAX_VCPUS to determine the maximum count */
    if ((ret = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS)) > 0)
        goto cleanup;
#endif /* KVM_CAP_MAX_VCPUS */

    /* as a fallback get KVM_CAP_NR_VCPUS (the recommended maximum number of
     * vcpus). Note that on most machines this is set to 160. */
    if ((ret = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS)) > 0)
        goto cleanup;

    /* if KVM_CAP_NR_VCPUS doesn't exist either, kernel documentation states
     * that 4 should be used as the maximum number of cpus */
    ret = 4;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


static char *
qemuConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(0, NULL);

    if (virConnectGetSysinfoEnsureACL(conn) < 0)
        return NULL;

    if (!driver->hostsysinfo) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Host SMBIOS information is not available"));
        return NULL;
    }

    if (virSysinfoFormat(&buf, driver->hostsysinfo) < 0)
        return NULL;
    if (virBufferCheckError(&buf) < 0)
        return NULL;
    return virBufferContentAndReset(&buf);
}

static int
qemuConnectGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED, const char *type)
{
    if (virConnectGetMaxVcpusEnsureACL(conn) < 0)
        return -1;

    if (!type)
        return 16;

    if (STRCASEEQ(type, "qemu"))
        return 16;

    if (STRCASEEQ(type, "kvm"))
        return kvmGetMaxVCPUs();

    if (STRCASEEQ(type, "kqemu"))
        return 1;

    virReportError(VIR_ERR_INVALID_ARG,
                   _("unknown type '%s'"), type);
    return -1;
}


static char *qemuConnectGetCapabilities(virConnectPtr conn) {
    virQEMUDriverPtr driver = conn->privateData;
    virCapsPtr caps = NULL;
    char *xml = NULL;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = virQEMUDriverGetCapabilities(driver, true)))
        goto cleanup;

    xml = virCapabilitiesFormatXML(caps);
    virObjectUnref(caps);

 cleanup:

    return xml;
}


static int
qemuGetProcessInfo(unsigned long long *cpuTime, int *lastCpu, long *vm_rss,
                   pid_t pid, int tid)
{
    char *proc;
    FILE *pidinfo;
    unsigned long long usertime = 0, systime = 0;
    long rss = 0;
    int cpu = 0;
    int ret;

    /* In general, we cannot assume pid_t fits in int; but /proc parsing
     * is specific to Linux where int works fine.  */
    if (tid)
        ret = virAsprintf(&proc, "/proc/%d/task/%d/stat", (int) pid, tid);
    else
        ret = virAsprintf(&proc, "/proc/%d/stat", (int) pid);
    if (ret < 0)
        return -1;

    pidinfo = fopen(proc, "r");
    VIR_FREE(proc);

    /* See 'man proc' for information about what all these fields are. We're
     * only interested in a very few of them */
    if (!pidinfo ||
        fscanf(pidinfo,
               /* pid -> stime */
               "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu"
               /* cutime -> endcode */
               "%*d %*d %*d %*d %*d %*d %*u %*u %ld %*u %*u %*u"
               /* startstack -> processor */
               "%*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %d",
               &usertime, &systime, &rss, &cpu) != 4) {
        VIR_WARN("cannot parse process status data");
    }

    /* We got jiffies
     * We want nanoseconds
     * _SC_CLK_TCK is jiffies per second
     * So calculate thus....
     */
    if (cpuTime)
        *cpuTime = 1000ull * 1000ull * 1000ull * (usertime + systime)
            / (unsigned long long)sysconf(_SC_CLK_TCK);
    if (lastCpu)
        *lastCpu = cpu;

    if (vm_rss)
        *vm_rss = rss * virGetSystemPageSizeKB();


    VIR_DEBUG("Got status for %d/%d user=%llu sys=%llu cpu=%d rss=%ld",
              (int) pid, tid, usertime, systime, cpu, rss);

    VIR_FORCE_FCLOSE(pidinfo);

    return 0;
}


static int
qemuDomainHelperGetVcpus(virDomainObjPtr vm,
                         virVcpuInfoPtr info,
                         int maxinfo,
                         unsigned char *cpumaps,
                         int maplen)
{
    size_t ncpuinfo = 0;
    size_t i;

    if (maxinfo == 0)
        return 0;

    if (!qemuDomainHasVcpuPids(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cpu affinity is not supported"));
        return -1;
    }

    if (info)
        memset(info, 0, sizeof(*info) * maxinfo);

    if (cpumaps)
        memset(cpumaps, 0, sizeof(*cpumaps) * maxinfo);

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def) && ncpuinfo < maxinfo; i++) {
        virDomainVcpuInfoPtr vcpu = virDomainDefGetVcpu(vm->def, i);
        pid_t vcpupid = qemuDomainGetVcpuPid(vm, i);

        if (!vcpu->online)
            continue;

        if (info) {
            info[i].number = i;
            info[i].state = VIR_VCPU_RUNNING;

            if (qemuGetProcessInfo(&(info[i].cpuTime), &(info[i].cpu), NULL,
                                   vm->pid, vcpupid) < 0) {
                virReportSystemError(errno, "%s",
                                     _("cannot get vCPU placement & pCPU time"));
                return -1;
            }
        }

        if (cpumaps) {
            unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, i);
            virBitmapPtr map = NULL;

            if (!(map = virProcessGetAffinity(vcpupid)))
                return -1;

            virBitmapToDataBuf(map, cpumap, maplen);
            virBitmapFree(map);
        }

        ncpuinfo++;
    }

    return ncpuinfo;
}


static virDomainPtr qemuDomainLookupByID(virConnectPtr conn,
                                         int id)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm  = virDomainObjListFindByID(driver->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id %d"), id);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr qemuDomainLookupByUUID(virConnectPtr conn,
                                           const unsigned char *uuid)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUIDRef(driver->domains, uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr qemuDomainLookupByName(virConnectPtr conn,
                                           const char *name)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}


static int qemuDomainIsActive(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int qemuDomainIsPersistent(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsPersistentEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int qemuDomainIsUpdated(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsUpdatedEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->updated;

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int qemuConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;
    unsigned int qemuVersion = 0;
    virCapsPtr caps = NULL;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virQEMUCapsGetDefaultVersion(caps,
                                     driver->qemuCapsCache,
                                     &qemuVersion) < 0)
        goto cleanup;

    *version = qemuVersion;
    ret = 0;

 cleanup:
    virObjectUnref(caps);
    return ret;
}


static char *qemuConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}


static int qemuConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    virQEMUDriverPtr driver = conn->privateData;
    int n;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     virConnectListDomainsCheckACL, conn);

    return n;
}

static int qemuConnectNumOfDomains(virConnectPtr conn)
{
    virQEMUDriverPtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListNumOfDomains(driver->domains, true,
                                     virConnectNumOfDomainsCheckACL, conn);

    return n;
}


static int
qemuCanonicalizeMachine(virDomainDefPtr def, virQEMUCapsPtr qemuCaps)
{
    const char *canon;

    if (!(canon = virQEMUCapsGetCanonicalMachine(qemuCaps, def->os.machine)))
        return 0;

    if (STRNEQ(canon, def->os.machine)) {
        char *tmp;
        if (VIR_STRDUP(tmp, canon) < 0)
            return -1;
        VIR_FREE(def->os.machine);
        def->os.machine = tmp;
    }

    return 0;
}


static virDomainPtr qemuDomainCreateXML(virConnectPtr conn,
                                        const char *xml,
                                        unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virObjectEventPtr event = NULL;
    virObjectEventPtr event2 = NULL;
    unsigned int start_flags = VIR_QEMU_PROCESS_START_COLD;
    virQEMUCapsPtr qemuCaps = NULL;
    virCapsPtr caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE;
    if (flags & VIR_DOMAIN_START_PAUSED)
        start_flags |= VIR_QEMU_PROCESS_START_PAUSED;
    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_QEMU_PROCESS_START_AUTODESTROY;

    virNWFilterReadLockFilterUpdates();

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        parse_flags)))
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, def->emulator)))
        goto cleanup;

    if (qemuCanonicalizeMachine(def, qemuCaps) < 0)
        goto cleanup;

    if (qemuDomainAssignAddresses(def, qemuCaps, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    virObjectRef(vm);
    def = NULL;

    if (qemuProcessBeginJob(driver, vm) < 0) {
        qemuDomainRemoveInactive(driver, vm);
        goto cleanup;
    }

    if (qemuProcessStart(conn, driver, vm, QEMU_ASYNC_JOB_START,
                         NULL, -1, NULL, NULL,
                         VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                         start_flags) < 0) {
        virDomainAuditStart(vm, "booted", false);
        qemuProcessEndJob(driver, vm);
        qemuDomainRemoveInactive(driver, vm);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    if (event && (flags & VIR_DOMAIN_START_PAUSED)) {
        /* There are two classes of event-watching clients - those
         * that only care about on/off (and must see a started event
         * no matter what, but don't care about suspend events), and
         * those that also care about running/paused.  To satisfy both
         * client types, we have to send two events.  */
        event2 = virDomainEventLifecycleNewFromObj(vm,
                                          VIR_DOMAIN_EVENT_SUSPENDED,
                                          VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }
    virDomainAuditStart(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    qemuProcessEndJob(driver, vm);

 cleanup:
    virDomainDefFree(def);
    virDomainObjEndAPI(&vm);
    if (event) {
        qemuDomainEventQueue(driver, event);
        qemuDomainEventQueue(driver, event2);
    }
    virObjectUnref(caps);
    virObjectUnref(qemuCaps);
    virNWFilterUnlockFilterUpdates();
    return dom;
}


static int qemuDomainSuspend(virDomainPtr dom)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virObjectEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;
    virDomainPausedReason reason;
    int eventDetail;
    int state;
    virQEMUDriverConfigPtr cfg = NULL;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    cfg = virQEMUDriverGetConfig(driver);
    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_SUSPEND) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT) {
        reason = VIR_DOMAIN_PAUSED_MIGRATION;
        eventDetail = VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED;
    } else if (priv->job.asyncJob == QEMU_ASYNC_JOB_SNAPSHOT) {
        reason = VIR_DOMAIN_PAUSED_SNAPSHOT;
        eventDetail = -1; /* don't create lifecycle events when doing snapshot */
    } else {
        reason = VIR_DOMAIN_PAUSED_USER;
        eventDetail = VIR_DOMAIN_EVENT_SUSPENDED_PAUSED;
    }

    state = virDomainObjGetState(vm, NULL);
    if (state == VIR_DOMAIN_PMSUSPENDED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is pmsuspended"));
        goto endjob;
    } else if (state != VIR_DOMAIN_PAUSED) {
        if (qemuProcessStopCPUs(driver, vm, reason, QEMU_ASYNC_JOB_NONE) < 0)
            goto endjob;

        if (eventDetail >= 0) {
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_SUSPENDED,
                                             eventDetail);
        }
    }
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;
    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);

    qemuDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}


static int qemuDomainResume(virDomainPtr dom)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virObjectEventPtr event = NULL;
    int state;
    virQEMUDriverConfigPtr cfg = NULL;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    state = virDomainObjGetState(vm, NULL);
    if (state == VIR_DOMAIN_PMSUSPENDED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is pmsuspended"));
        goto endjob;
    } else if (state == VIR_DOMAIN_PAUSED) {
        if (qemuProcessStartCPUs(driver, vm, dom->conn,
                                 VIR_DOMAIN_RUNNING_UNPAUSED,
                                 QEMU_ASYNC_JOB_NONE) < 0) {
            if (virGetLastError() == NULL)
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("resume operation failed"));
            goto endjob;
        }
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;
    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}

static int qemuDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    bool useAgent = false, agentRequested, acpiRequested;
    bool isReboot = false;
    bool agentForced;
    int agentFlag = QEMU_AGENT_SHUTDOWN_POWERDOWN;

    virCheckFlags(VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN |
                  VIR_DOMAIN_SHUTDOWN_GUEST_AGENT, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (vm->def->onPoweroff == VIR_DOMAIN_LIFECYCLE_RESTART ||
        vm->def->onPoweroff == VIR_DOMAIN_LIFECYCLE_RESTART_RENAME) {
        isReboot = true;
        agentFlag = QEMU_AGENT_SHUTDOWN_REBOOT;
        VIR_INFO("Domain on_poweroff setting overridden, attempting reboot");
    }

    priv = vm->privateData;
    agentRequested = flags & VIR_DOMAIN_SHUTDOWN_GUEST_AGENT;
    acpiRequested  = flags & VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN;

    /* Prefer agent unless we were requested to not to. */
    if (agentRequested || (!flags && priv->agent))
        useAgent = true;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    agentForced = agentRequested && !acpiRequested;
    if (!qemuDomainAgentAvailable(vm, agentForced)) {
        if (agentForced)
            goto endjob;
        useAgent = false;
    }

    qemuDomainSetFakeReboot(driver, vm, isReboot);

    if (useAgent) {
        qemuDomainObjEnterAgent(vm);
        ret = qemuAgentShutdown(priv->agent, agentFlag);
        qemuDomainObjExitAgent(vm);
    }

    /* If we are not enforced to use just an agent, try ACPI
     * shutdown as well in case agent did not succeed.
     */
    if (!useAgent ||
        (ret < 0 && (acpiRequested || !flags))) {

        /* Even if agent failed, we have to check if guest went away
         * by itself while our locks were down.  */
        if (useAgent && !virDomainObjIsActive(vm)) {
            ret = 0;
            goto endjob;
        }

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSystemPowerdown(priv->mon);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int qemuDomainShutdown(virDomainPtr dom)
{
    return qemuDomainShutdownFlags(dom, 0);
}


static int
qemuDomainReboot(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    bool useAgent = false, agentRequested, acpiRequested;
    bool isReboot = true;
    bool agentForced;
    int agentFlag = QEMU_AGENT_SHUTDOWN_REBOOT;

    virCheckFlags(VIR_DOMAIN_REBOOT_ACPI_POWER_BTN |
                  VIR_DOMAIN_REBOOT_GUEST_AGENT, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_DESTROY ||
        vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_PRESERVE) {
        agentFlag = QEMU_AGENT_SHUTDOWN_POWERDOWN;
        isReboot = false;
        VIR_INFO("Domain on_reboot setting overridden, shutting down");
    }

    priv = vm->privateData;
    agentRequested = flags & VIR_DOMAIN_REBOOT_GUEST_AGENT;
    acpiRequested  = flags & VIR_DOMAIN_REBOOT_ACPI_POWER_BTN;

    /* Prefer agent unless we were requested to not to. */
    if (agentRequested || (!flags && priv->agent))
        useAgent = true;

    if (virDomainRebootEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    agentForced = agentRequested && !acpiRequested;
    if (!qemuDomainAgentAvailable(vm, agentForced)) {
        if (agentForced)
            goto endjob;
        useAgent = false;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainSetFakeReboot(driver, vm, isReboot);

    if (useAgent) {
        qemuDomainObjEnterAgent(vm);
        ret = qemuAgentShutdown(priv->agent, agentFlag);
        qemuDomainObjExitAgent(vm);
    }

    /* If we are not enforced to use just an agent, try ACPI
     * shutdown as well in case agent did not succeed.
     */
    if ((!useAgent) ||
        (ret < 0 && (acpiRequested || !flags))) {
#if WITH_YAJL
        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MONITOR_JSON)) {
            if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NO_SHUTDOWN)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("ACPI reboot is not supported with this QEMU binary"));
                goto endjob;
            }
        } else {
#endif
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("ACPI reboot is not supported without the JSON monitor"));
            goto endjob;
#if WITH_YAJL
        }
#endif
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSystemPowerdown(priv->mon);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainReset(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainResetEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSystemReset(priv->mon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    priv->fakeReboot = false;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


/* Count how many snapshots in a set are external snapshots or checkpoints.  */
static void
qemuDomainSnapshotCountExternal(void *payload,
                                const void *name ATTRIBUTE_UNUSED,
                                void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    int *count = data;

    if (virDomainSnapshotIsExternal(snap))
        (*count)++;
}

static int
qemuDomainDestroyFlags(virDomainPtr dom,
                       unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virObjectEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;
    unsigned int stopFlags = 0;

    virCheckFlags(VIR_DOMAIN_DESTROY_GRACEFUL, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    qemuDomainSetFakeReboot(driver, vm, false);

    if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_IN)
        stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;

    /* We need to prevent monitor EOF callback from doing our work (and sending
     * misleading events) while the vm is unlocked inside BeginJob/ProcessKill API
     */
    priv->beingDestroyed = true;

    /* Although qemuProcessStop does this already, there may
     * be an outstanding job active. We want to make sure we
     * can kill the process even if a job is active. Killing
     * it now means the job will be released
     */
    if (flags & VIR_DOMAIN_DESTROY_GRACEFUL) {
        if (qemuProcessKill(vm, 0) < 0) {
            priv->beingDestroyed = false;
            goto cleanup;
        }
    } else {
        if (qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_FORCE) < 0) {
            priv->beingDestroyed = false;
            goto cleanup;
        }
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_DESTROY) < 0)
        goto cleanup;

    priv->beingDestroyed = false;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED, stopFlags);
    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    virDomainAuditStop(vm, "destroyed");

    ret = 0;
 endjob:
    qemuDomainObjEndJob(driver, vm);
    if (ret == 0)
        qemuDomainRemoveInactive(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    return ret;
}

static int
qemuDomainDestroy(virDomainPtr dom)
{
    return qemuDomainDestroyFlags(dom, 0);
}

static char *qemuDomainGetOSType(virDomainPtr dom) {
    virDomainObjPtr vm;
    char *type = NULL;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ignore_value(VIR_STRDUP(type, virDomainOSTypeToString(vm->def->os.type)));

 cleanup:
    virDomainObjEndAPI(&vm);
    return type;
}

/* Returns max memory in kb, 0 if error */
static unsigned long long
qemuDomainGetMaxMemory(virDomainPtr dom)
{
    virDomainObjPtr vm;
    unsigned long long ret = 0;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetMaxMemoryEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainDefGetMemoryActual(vm->def);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int qemuDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                                    unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1, r;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetMemoryFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;


    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        /* resize the maximum memory */

        if (def) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot resize the maximum memory on an "
                             "active domain"));
            goto endjob;
        }

        if (persistentDef) {
            /* resizing memory with NUMA nodes specified doesn't work as there
             * is no way to change the individual node sizes with this API */
            if (virDomainNumaGetNodeCount(persistentDef->numa) > 0) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("initial memory size of a domain with NUMA "
                                 "nodes cannot be modified with this API"));
                goto endjob;
            }

            if (persistentDef->mem.max_memory &&
                persistentDef->mem.max_memory < newmem) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("cannot set initial memory size greater than "
                                 "the maximum memory size"));
                goto endjob;
            }

            virDomainDefSetMemoryTotal(persistentDef, newmem);

            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(cfg->configDir, persistentDef);
            goto endjob;
        }

    } else {
        /* resize the current memory */
        unsigned long oldmax = 0;

        if (def)
            oldmax = virDomainDefGetMemoryActual(def);
        if (persistentDef) {
            if (!oldmax || oldmax > virDomainDefGetMemoryActual(persistentDef))
                oldmax = virDomainDefGetMemoryActual(persistentDef);
        }

        if (newmem > oldmax) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("cannot set memory higher than max memory"));
            goto endjob;
        }

        if (def) {
            priv = vm->privateData;
            qemuDomainObjEnterMonitor(driver, vm);
            r = qemuMonitorSetBalloon(priv->mon, newmem);
            if (qemuDomainObjExitMonitor(driver, vm) < 0 || r < 0)
                goto endjob;

            /* Lack of balloon support is a fatal error */
            if (r == 0) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("Unable to change memory of active domain without "
                                 "the balloon device and guest OS balloon driver"));
                goto endjob;
            }
        }

        if (persistentDef) {
            persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(cfg->configDir, persistentDef);
            goto endjob;
        }
    }

    ret = 0;
 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int qemuDomainSetMemory(virDomainPtr dom, unsigned long newmem)
{
    return qemuDomainSetMemoryFlags(dom, newmem, VIR_DOMAIN_AFFECT_LIVE);
}

static int qemuDomainSetMaxMemory(virDomainPtr dom, unsigned long memory)
{
    return qemuDomainSetMemoryFlags(dom, memory, VIR_DOMAIN_MEM_MAXIMUM);
}

static int qemuDomainSetMemoryStatsPeriod(virDomainPtr dom, int period,
                                          unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1, r;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetMemoryStatsPeriodEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    /* Set the balloon driver collection interval */
    priv = vm->privateData;

    if (def) {
        if (!def->memballoon ||
            def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Memory balloon model must be virtio to set the"
                             " collection period"));
            goto endjob;
        }

        qemuDomainObjEnterMonitor(driver, vm);
        r = qemuMonitorSetMemoryStatsPeriod(priv->mon, period);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto endjob;
        if (r < 0) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("unable to set balloon driver collection period"));
            goto endjob;
        }

        def->memballoon->period = period;
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;
    }

    if (persistentDef) {
        if (!persistentDef->memballoon ||
            persistentDef->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Memory balloon model must be virtio to set the"
                             " collection period"));
            goto endjob;
        }
        persistentDef->memballoon->period = period;
        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        goto endjob;
    }

    ret = 0;
 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int qemuDomainInjectNMI(virDomainPtr domain, unsigned int flags)
{
    virQEMUDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    if (virDomainInjectNMIEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorInjectNMI(priv->mon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int qemuDomainSendKey(virDomainPtr domain,
                             unsigned int codeset,
                             unsigned int holdtime,
                             unsigned int *keycodes,
                             int nkeycodes,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    /* translate the keycode to RFB for qemu driver */
    if (codeset != VIR_KEYCODE_SET_RFB) {
        size_t i;
        int keycode;

        for (i = 0; i < nkeycodes; i++) {
            keycode = virKeycodeValueTranslate(codeset, VIR_KEYCODE_SET_RFB,
                                               keycodes[i]);
            if (keycode < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot translate keycode %u of %s codeset to rfb keycode"),
                               keycodes[i],
                               virKeycodeSetTypeToString(codeset));
                return -1;
            }
            keycodes[i] = keycode;
        }
    }

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSendKeyEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSendKey(priv->mon, holdtime, keycodes, nkeycodes);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainGetInfo(virDomainPtr dom,
                  virDomainInfoPtr info)
{
    unsigned long long maxmem;
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainUpdateCurrentMemorySize(driver, vm) < 0)
        goto cleanup;

    memset(info, 0, sizeof(*info));

    info->state = virDomainObjGetState(vm, NULL);

    maxmem = virDomainDefGetMemoryActual(vm->def);
    if (VIR_ASSIGN_IS_OVERFLOW(info->maxMem, maxmem)) {
        virReportError(VIR_ERR_OVERFLOW, "%s",
                       _("Initial memory size too large"));
        goto cleanup;
    }

    if (VIR_ASSIGN_IS_OVERFLOW(info->memory, vm->def->mem.cur_balloon)) {
        virReportError(VIR_ERR_OVERFLOW, "%s",
                       _("Current memory size too large"));
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        if (qemuGetProcessInfo(&(info->cpuTime), NULL, NULL, vm->pid, 0) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("cannot read cputime for domain"));
            goto cleanup;
        }
    }

    if (VIR_ASSIGN_IS_OVERFLOW(info->nrVirtCpu, virDomainDefGetVcpus(vm->def))) {
        virReportError(VIR_ERR_OVERFLOW, "%s", _("cpu count too large"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainGetState(virDomainPtr dom,
                   int *state,
                   int *reason,
                   unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainGetControlInfo(virDomainPtr dom,
                          virDomainControlInfoPtr info,
                          unsigned int flags)
{
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetControlInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;

    memset(info, 0, sizeof(*info));

    if (priv->monError) {
        info->state = VIR_DOMAIN_CONTROL_ERROR;
        info->details = VIR_DOMAIN_CONTROL_ERROR_REASON_MONITOR;
    } else if (priv->job.active) {
        if (virTimeMillisNow(&info->stateTime) < 0)
            goto cleanup;
        if (priv->job.current) {
            info->state = VIR_DOMAIN_CONTROL_JOB;
            info->stateTime -= priv->job.current->started;
        } else {
            if (priv->monStart > 0) {
                info->state = VIR_DOMAIN_CONTROL_OCCUPIED;
                info->stateTime -= priv->monStart;
            } else {
                /* At this point the domain has an active job, but monitor was
                 * not entered and the domain object lock is not held thus we
                 * are stuck in the job forever due to a programming error.
                 */
                info->state = VIR_DOMAIN_CONTROL_ERROR;
                info->details = VIR_DOMAIN_CONTROL_ERROR_REASON_INTERNAL;
                info->stateTime = 0;
            }
        }
    } else {
        info->state = VIR_DOMAIN_CONTROL_OK;
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


/* It would be nice to replace 'Qemud' with 'Qemu' but
 * this magic string is ABI, so it can't be changed
 */
#define QEMU_SAVE_MAGIC   "LibvirtQemudSave"
#define QEMU_SAVE_PARTIAL "LibvirtQemudPart"
#define QEMU_SAVE_VERSION 2

verify(sizeof(QEMU_SAVE_MAGIC) == sizeof(QEMU_SAVE_PARTIAL));

typedef enum {
    QEMU_SAVE_FORMAT_RAW = 0,
    QEMU_SAVE_FORMAT_GZIP = 1,
    QEMU_SAVE_FORMAT_BZIP2 = 2,
    /*
     * Deprecated by xz and never used as part of a release
     * QEMU_SAVE_FORMAT_LZMA
     */
    QEMU_SAVE_FORMAT_XZ = 3,
    QEMU_SAVE_FORMAT_LZOP = 4,
    /* Note: add new members only at the end.
       These values are used in the on-disk format.
       Do not change or re-use numbers. */

    QEMU_SAVE_FORMAT_LAST
} virQEMUSaveFormat;

VIR_ENUM_DECL(qemuSaveCompression)
VIR_ENUM_IMPL(qemuSaveCompression, QEMU_SAVE_FORMAT_LAST,
              "raw",
              "gzip",
              "bzip2",
              "xz",
              "lzop")

VIR_ENUM_DECL(qemuDumpFormat)
VIR_ENUM_IMPL(qemuDumpFormat, VIR_DOMAIN_CORE_DUMP_FORMAT_LAST,
              "elf",
              "kdump-zlib",
              "kdump-lzo",
              "kdump-snappy")

typedef struct _virQEMUSaveHeader virQEMUSaveHeader;
typedef virQEMUSaveHeader *virQEMUSaveHeaderPtr;
struct _virQEMUSaveHeader {
    char magic[sizeof(QEMU_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t xml_len;
    uint32_t was_running;
    uint32_t compressed;
    uint32_t unused[15];
};

static inline void
bswap_header(virQEMUSaveHeaderPtr hdr)
{
    hdr->version = bswap_32(hdr->version);
    hdr->xml_len = bswap_32(hdr->xml_len);
    hdr->was_running = bswap_32(hdr->was_running);
    hdr->compressed = bswap_32(hdr->compressed);
}


/* return -errno on failure, or 0 on success */
static int
qemuDomainSaveHeader(int fd, const char *path, const char *xml,
                     virQEMUSaveHeaderPtr header)
{
    int ret = 0;

    if (safewrite(fd, header, sizeof(*header)) != sizeof(*header)) {
        ret = -errno;
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to write header to domain save file '%s'"),
                       path);
        goto endjob;
    }

    if (safewrite(fd, xml, header->xml_len) != header->xml_len) {
        ret = -errno;
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to write xml to '%s'"), path);
        goto endjob;
    }
 endjob:
    return ret;
}

/* Given a virQEMUSaveFormat compression level, return the name
 * of the program to run, or NULL if no program is needed.  */
static const char *
qemuCompressProgramName(int compress)
{
    return (compress == QEMU_SAVE_FORMAT_RAW ? NULL :
            qemuSaveCompressionTypeToString(compress));
}

static virCommandPtr
qemuCompressGetCommand(virQEMUSaveFormat compression)
{
    virCommandPtr ret = NULL;
    const char *prog = qemuSaveCompressionTypeToString(compression);

    if (!prog) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Invalid compressed save format %d"),
                       compression);
        return NULL;
    }

    ret = virCommandNew(prog);
    virCommandAddArg(ret, "-dc");

    switch (compression) {
    case QEMU_SAVE_FORMAT_LZOP:
        virCommandAddArg(ret, "--ignore-warn");
        break;
    default:
        break;
    }

    return ret;
}

/* Internal function to properly create or open existing files, with
 * ownership affected by qemu driver setup and domain DAC label.  */
static int
qemuOpenFile(virQEMUDriverPtr driver,
             virDomainObjPtr vm,
             const char *path, int oflags,
             bool *needUnlink, bool *bypassSecurityDriver)
{
    int ret = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    uid_t user = cfg->user;
    gid_t group = cfg->group;
    bool dynamicOwnership = cfg->dynamicOwnership;
    virSecurityLabelDefPtr seclabel;

    virObjectUnref(cfg);

    /* TODO: Take imagelabel into account? */
    if (vm &&
        (seclabel = virDomainDefGetSecurityLabelDef(vm->def, "dac")) != NULL &&
        seclabel->label != NULL &&
        (virParseOwnershipIds(seclabel->label, &user, &group) < 0))
        goto cleanup;

    ret = qemuOpenFileAs(user, group, dynamicOwnership,
                         path, oflags, needUnlink, bypassSecurityDriver);

 cleanup:
    return ret;
}

static int
qemuOpenFileAs(uid_t fallback_uid, gid_t fallback_gid,
               bool dynamicOwnership,
               const char *path, int oflags,
               bool *needUnlink, bool *bypassSecurityDriver)
{
    struct stat sb;
    bool is_reg = true;
    bool need_unlink = false;
    bool bypass_security = false;
    unsigned int vfoflags = 0;
    int fd = -1;
    int path_shared = virFileIsSharedFS(path);
    uid_t uid = geteuid();
    gid_t gid = getegid();

    /* path might be a pre-existing block dev, in which case
     * we need to skip the create step, and also avoid unlink
     * in the failure case */
    if (oflags & O_CREAT) {
        need_unlink = true;

        /* Don't force chown on network-shared FS
         * as it is likely to fail. */
        if (path_shared <= 0 || dynamicOwnership)
            vfoflags |= VIR_FILE_OPEN_FORCE_OWNER;

        if (stat(path, &sb) == 0) {
            /* It already exists, we don't want to delete it on error */
            need_unlink = false;

            is_reg = !!S_ISREG(sb.st_mode);
            /* If the path is regular file which exists
             * already and dynamic_ownership is off, we don't
             * want to change its ownership, just open it as-is */
            if (is_reg && !dynamicOwnership) {
                uid = sb.st_uid;
                gid = sb.st_gid;
            }
        }
    }

    /* First try creating the file as root */
    if (!is_reg) {
        if ((fd = open(path, oflags & ~O_CREAT)) < 0) {
            fd = -errno;
            goto error;
        }
    } else {
        if ((fd = virFileOpenAs(path, oflags, S_IRUSR | S_IWUSR, uid, gid,
                                vfoflags | VIR_FILE_OPEN_NOFORK)) < 0) {
            /* If we failed as root, and the error was permission-denied
               (EACCES or EPERM), assume it's on a network-connected share
               where root access is restricted (eg, root-squashed NFS). If the
               qemu user is non-root, just set a flag to
               bypass security driver shenanigans, and retry the operation
               after doing setuid to qemu user */
            if ((fd != -EACCES && fd != -EPERM) || fallback_uid == geteuid())
                goto error;

            /* On Linux we can also verify the FS-type of the directory. */
            switch (path_shared) {
                case 1:
                    /* it was on a network share, so we'll continue
                     * as outlined above
                     */
                    break;

                case -1:
                    virReportSystemError(-fd, oflags & O_CREAT
                                         ? _("Failed to create file "
                                             "'%s': couldn't determine fs type")
                                         : _("Failed to open file "
                                             "'%s': couldn't determine fs type"),
                                         path);
                    goto cleanup;

                case 0:
                default:
                    /* local file - log the error returned by virFileOpenAs */
                    goto error;
            }

            /* If we created the file above, then we need to remove it;
             * otherwise, the next attempt to create will fail. If the
             * file had already existed before we got here, then we also
             * don't want to delete it and allow the following to succeed
             * or fail based on existing protections
             */
            if (need_unlink)
                unlink(path);

            /* Retry creating the file as qemu user */

            /* Since we're passing different modes... */
            vfoflags |= VIR_FILE_OPEN_FORCE_MODE;

            if ((fd = virFileOpenAs(path, oflags,
                                    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP,
                                    fallback_uid, fallback_gid,
                                    vfoflags | VIR_FILE_OPEN_FORK)) < 0) {
                virReportSystemError(-fd, oflags & O_CREAT
                                     ? _("Error from child process creating '%s'")
                                     : _("Error from child process opening '%s'"),
                                     path);
                goto cleanup;
            }

            /* Since we had to setuid to create the file, and the fstype
               is NFS, we assume it's a root-squashing NFS share, and that
               the security driver stuff would have failed anyway */

            bypass_security = true;
        }
    }
 cleanup:
    if (needUnlink)
        *needUnlink = need_unlink;
    if (bypassSecurityDriver)
        *bypassSecurityDriver = bypass_security;
    return fd;

 error:
    virReportSystemError(-fd, oflags & O_CREAT
                         ? _("Failed to create file '%s'")
                         : _("Failed to open file '%s'"),
                         path);
    goto cleanup;
}

/* Helper function to execute a migration to file with a correct save header
 * the caller needs to make sure that the processors are stopped and do all other
 * actions besides saving memory */
static int
qemuDomainSaveMemory(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     const char *path,
                     const char *domXML,
                     int compressed,
                     bool was_running,
                     unsigned int flags,
                     qemuDomainAsyncJob asyncJob)
{
    virQEMUSaveHeader header;
    bool bypassSecurityDriver = false;
    bool needUnlink = false;
    int ret = -1;
    int fd = -1;
    int directFlag = 0;
    virFileWrapperFdPtr wrapperFd = NULL;
    unsigned int wrapperFlags = VIR_FILE_WRAPPER_NON_BLOCKING;
    unsigned long long pad;
    unsigned long long offset;
    size_t len;
    char *xml = NULL;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QEMU_SAVE_PARTIAL, sizeof(header.magic));
    header.version = QEMU_SAVE_VERSION;
    header.was_running = was_running ? 1 : 0;

    header.compressed = compressed;

    len = strlen(domXML) + 1;
    offset = sizeof(header) + len;

    /* Due to way we append QEMU state on our header with dd,
     * we need to ensure there's a 512 byte boundary. Unfortunately
     * we don't have an explicit offset in the header, so we fake
     * it by padding the XML string with NUL bytes.  Additionally,
     * we want to ensure that virDomainSaveImageDefineXML can supply
     * slightly larger XML, so we add a minimum padding prior to
     * rounding out to page boundaries.
     */
    pad = 1024;
    pad += (QEMU_MONITOR_MIGRATE_TO_FILE_BS -
            ((offset + pad) % QEMU_MONITOR_MIGRATE_TO_FILE_BS));
    if (VIR_ALLOC_N(xml, len + pad) < 0)
        goto cleanup;
    strcpy(xml, domXML);

    offset += pad;
    header.xml_len = len;

    /* Obtain the file handle.  */
    if ((flags & VIR_DOMAIN_SAVE_BYPASS_CACHE)) {
        wrapperFlags |= VIR_FILE_WRAPPER_BYPASS_CACHE;
        directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("bypass cache unsupported by this system"));
            goto cleanup;
        }
    }
    fd = qemuOpenFile(driver, vm, path,
                      O_WRONLY | O_TRUNC | O_CREAT | directFlag,
                      &needUnlink, &bypassSecurityDriver);
    if (fd < 0)
        goto cleanup;

    if (virSecurityManagerSetImageFDLabel(driver->securityManager, vm->def, fd) < 0)
        goto cleanup;

    if (!(wrapperFd = virFileWrapperFdNew(&fd, path, wrapperFlags)))
        goto cleanup;

    /* Write header to file, followed by XML */
    if (qemuDomainSaveHeader(fd, path, xml, &header) < 0)
        goto cleanup;

    /* Perform the migration */
    if (qemuMigrationToFile(driver, vm, fd, offset, path,
                            qemuCompressProgramName(compressed),
                            bypassSecurityDriver,
                            asyncJob) < 0)
        goto cleanup;

    /* Touch up file header to mark image complete. */

    /* Reopen the file to touch up the header, since we aren't set
     * up to seek backwards on wrapperFd.  The reopened fd will
     * trigger a single page of file system cache pollution, but
     * that's acceptable.  */
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("unable to close %s"), path);
        goto cleanup;
    }

    if (virFileWrapperFdClose(wrapperFd) < 0)
        goto cleanup;

    if ((fd = qemuOpenFile(driver, vm, path, O_WRONLY, NULL, NULL)) < 0)
        goto cleanup;

    memcpy(header.magic, QEMU_SAVE_MAGIC, sizeof(header.magic));

    if (safewrite(fd, &header, sizeof(header)) != sizeof(header)) {
        virReportSystemError(errno, _("unable to write %s"), path);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("unable to close %s"), path);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    virFileWrapperFdFree(wrapperFd);
    VIR_FREE(xml);

    if (ret < 0 && needUnlink)
        unlink(path);

    return ret;
}

/* The vm must be active + locked. Vm will be unlocked and
 * potentially free'd after this returns (eg transient VMs are freed
 * shutdown). So 'vm' must not be referenced by the caller after
 * this returns (whether returning success or failure).
 */
static int
qemuDomainSaveInternal(virQEMUDriverPtr driver, virDomainPtr dom,
                       virDomainObjPtr vm, const char *path,
                       int compressed, const char *xmlin, unsigned int flags)
{
    char *xml = NULL;
    bool was_running = false;
    int ret = -1;
    virObjectEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!qemuMigrationIsAllowed(driver, vm, false, 0))
        goto cleanup;

    if (qemuDomainObjBeginAsyncJob(driver, vm, QEMU_ASYNC_JOB_SAVE) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto endjob;
    }

    priv->job.current->type = VIR_DOMAIN_JOB_UNBOUNDED;

    /* Pause */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        was_running = true;
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SAVE,
                                QEMU_ASYNC_JOB_SAVE) < 0)
            goto endjob;

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto endjob;
        }
    }

   /* libvirt.c already guaranteed these two flags are exclusive.  */
    if (flags & VIR_DOMAIN_SAVE_RUNNING)
        was_running = true;
    else if (flags & VIR_DOMAIN_SAVE_PAUSED)
        was_running = false;

    /* Get XML for the domain.  Restore needs only the inactive xml,
     * including secure.  We should get the same result whether xmlin
     * is NULL or whether it was the live xml of the domain moments
     * before.  */
    if (xmlin) {
        virDomainDefPtr def = NULL;

        if (!(def = virDomainDefParseString(xmlin, caps, driver->xmlopt,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE))) {
            goto endjob;
        }
        if (!qemuDomainDefCheckABIStability(driver, vm->def, def)) {
            virDomainDefFree(def);
            goto endjob;
        }
        xml = qemuDomainDefFormatLive(driver, def, true, true);
    } else {
        xml = qemuDomainDefFormatLive(driver, vm->def, true, true);
    }
    if (!xml) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("failed to get domain xml"));
        goto endjob;
    }

    ret = qemuDomainSaveMemory(driver, vm, path, xml, compressed,
                               was_running, flags, QEMU_ASYNC_JOB_SAVE);
    if (ret < 0)
        goto endjob;

    if (!(flags&VIR_DOMAIN_SAVE_NOT_SHUTDOWN)) {
        /* Shut it down */
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SAVED, 0);
        virDomainAuditStop(vm, "saved");
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                                  VIR_DOMAIN_EVENT_STOPPED_SAVED);
    }
 endjob:
    if (ret < 0) {
        if (was_running && virDomainObjIsActive(vm)) {
            virErrorPtr save_err = virSaveLastError();
            if (qemuProcessStartCPUs(driver, vm, dom->conn,
                                     VIR_DOMAIN_RUNNING_SAVE_CANCELED,
                                     QEMU_ASYNC_JOB_SAVE) < 0) {
                VIR_WARN("Unable to resume guest CPUs after save failure");
                qemuDomainEventQueue(driver,
                                     virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR));
            }
            virSetError(save_err);
            virFreeError(save_err);
        }
    }
    qemuDomainObjEndAsyncJob(driver, vm);
    if (ret == 0)
        qemuDomainRemoveInactive(driver, vm);

 cleanup:
    VIR_FREE(xml);
    qemuDomainEventQueue(driver, event);
    virObjectUnref(caps);
    return ret;
}

/* Returns true if a compression program is available in PATH */
static bool
qemuCompressProgramAvailable(virQEMUSaveFormat compress)
{
    char *path;

    if (compress == QEMU_SAVE_FORMAT_RAW)
        return true;

    if (!(path = virFindFileInPath(qemuSaveCompressionTypeToString(compress))))
        return false;

    VIR_FREE(path);
    return true;
}

static int
qemuDomainSaveFlags(virDomainPtr dom, const char *path, const char *dxml,
                    unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    int compressed = QEMU_SAVE_FORMAT_RAW;
    int ret = -1;
    virDomainObjPtr vm = NULL;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE |
                  VIR_DOMAIN_SAVE_RUNNING |
                  VIR_DOMAIN_SAVE_PAUSED |
                  VIR_DOMAIN_SAVE_NOT_SHUTDOWN, -1);

    cfg = virQEMUDriverGetConfig(driver);
    if (cfg->saveImageFormat) {
        compressed = qemuSaveCompressionTypeFromString(cfg->saveImageFormat);
        if (compressed < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Invalid save image format specified "
                             "in configuration file"));
            goto cleanup;
        }
        if (!qemuCompressProgramAvailable(compressed)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Compression program for image format "
                             "in configuration file isn't available"));
            goto cleanup;
        }
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSaveFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    ret = qemuDomainSaveInternal(driver, dom, vm, path, compressed,
                                 dxml, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainSave(virDomainPtr dom, const char *path)
{
    return qemuDomainSaveFlags(dom, path, NULL, 0);
}

static char *
qemuDomainManagedSavePath(virQEMUDriverPtr driver, virDomainObjPtr vm)
{
    char *ret;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (virAsprintf(&ret, "%s/%s.save", cfg->saveDir, vm->def->name) < 0) {
        virObjectUnref(cfg);
        return NULL;
    }

    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virQEMUDriverConfigPtr cfg = NULL;
    int compressed = QEMU_SAVE_FORMAT_RAW;
    virDomainObjPtr vm;
    char *name = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE |
                  VIR_DOMAIN_SAVE_RUNNING |
                  VIR_DOMAIN_SAVE_PAUSED, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainManagedSaveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }
    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot do managed save for transient domain"));
        goto cleanup;
    }

    cfg = virQEMUDriverGetConfig(driver);
    if (cfg->saveImageFormat) {
        compressed = qemuSaveCompressionTypeFromString(cfg->saveImageFormat);
        if (compressed < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Invalid save image format specified "
                             "in configuration file"));
            goto cleanup;
        }
        if (!qemuCompressProgramAvailable(compressed)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Compression program for image format "
                             "in configuration file isn't available"));
            goto cleanup;
        }
    }

    if (!(name = qemuDomainManagedSavePath(driver, vm)))
        goto cleanup;

    VIR_INFO("Saving state of domain '%s' to '%s'", vm->def->name, name);

    ret = qemuDomainSaveInternal(driver, dom, vm, name,
                                 compressed, NULL, flags);
    if (ret == 0)
        vm->hasManagedSave = true;

 cleanup:
    virDomainObjEndAPI(&vm);
    VIR_FREE(name);
    virObjectUnref(cfg);

    return ret;
}

static int
qemuDomainManagedSaveLoad(virDomainObjPtr vm,
                          void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    char *name;
    int ret = -1;

    virObjectLock(vm);

    if (!(name = qemuDomainManagedSavePath(driver, vm)))
        goto cleanup;

    vm->hasManagedSave = virFileExists(name);

    ret = 0;
 cleanup:
    virObjectUnlock(vm);
    VIR_FREE(name);
    return ret;
}


static int
qemuDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainHasManagedSaveImageEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->hasManagedSave;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    char *name = NULL;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainManagedSaveRemoveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(name = qemuDomainManagedSavePath(driver, vm)))
        goto cleanup;

    if (unlink(name) < 0) {
        virReportSystemError(errno,
                             _("Failed to remove managed save file '%s'"),
                             name);
        goto cleanup;
    }

    vm->hasManagedSave = false;
    ret = 0;

 cleanup:
    VIR_FREE(name);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int qemuDumpToFd(virQEMUDriverPtr driver, virDomainObjPtr vm,
                        int fd, qemuDomainAsyncJob asyncJob,
                        const char *dumpformat)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DUMP_GUEST_MEMORY)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("dump-guest-memory is not supported"));
        return -1;
    }

    if (virSecurityManagerSetImageFDLabel(driver->securityManager, vm->def,
                                          fd) < 0)
        return -1;

    VIR_FREE(priv->job.current);
    priv->job.dump_memory_only = true;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (dumpformat) {
        ret = qemuMonitorGetDumpGuestMemoryCapability(priv->mon, dumpformat);

        if (ret <= 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unsupported dumpformat '%s' "
                             "for this QEMU binary"),
                           dumpformat);
            ret = -1;
            goto cleanup;
        }
    }

    ret = qemuMonitorDumpToFd(priv->mon, fd, dumpformat);

 cleanup:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));

    return ret;
}

static int
doCoreDump(virQEMUDriverPtr driver,
           virDomainObjPtr vm,
           const char *path,
           virQEMUSaveFormat compress,
           unsigned int dump_flags,
           unsigned int dumpformat)
{
    int fd = -1;
    int ret = -1;
    virFileWrapperFdPtr wrapperFd = NULL;
    int directFlag = 0;
    unsigned int flags = VIR_FILE_WRAPPER_NON_BLOCKING;
    const char *memory_dump_format = NULL;

    /* Create an empty file with appropriate ownership.  */
    if (dump_flags & VIR_DUMP_BYPASS_CACHE) {
        flags |= VIR_FILE_WRAPPER_BYPASS_CACHE;
        directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("bypass cache unsupported by this system"));
            goto cleanup;
        }
    }
    /* Core dumps usually imply last-ditch analysis efforts are
     * desired, so we intentionally do not unlink even if a file was
     * created.  */
    if ((fd = qemuOpenFile(driver, vm, path,
                           O_CREAT | O_TRUNC | O_WRONLY | directFlag,
                           NULL, NULL)) < 0)
        goto cleanup;

    if (!(wrapperFd = virFileWrapperFdNew(&fd, path, flags)))
        goto cleanup;

    if (dump_flags & VIR_DUMP_MEMORY_ONLY) {
        if (!(memory_dump_format = qemuDumpFormatTypeToString(dumpformat))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unknown dumpformat '%d'"), dumpformat);
            goto cleanup;
        }

        /* qemu dumps in "elf" without dumpformat set */
        if (STREQ(memory_dump_format, "elf"))
            memory_dump_format = NULL;

        ret = qemuDumpToFd(driver, vm, fd, QEMU_ASYNC_JOB_DUMP,
                           memory_dump_format);
    } else {
        if (dumpformat != VIR_DOMAIN_CORE_DUMP_FORMAT_RAW) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("kdump-compressed format is only supported with "
                             "memory-only dump"));
            goto cleanup;
        }

        if (!qemuMigrationIsAllowed(driver, vm, false, 0))
            goto cleanup;

        ret = qemuMigrationToFile(driver, vm, fd, 0, path,
                                  qemuCompressProgramName(compress), false,
                                  QEMU_ASYNC_JOB_DUMP);
    }

    if (ret < 0)
        goto cleanup;

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("unable to close file %s"),
                             path);
        goto cleanup;
    }
    if (virFileWrapperFdClose(wrapperFd) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    if (ret != 0)
        unlink(path);
    virFileWrapperFdFree(wrapperFd);
    return ret;
}

static virQEMUSaveFormat
getCompressionType(virQEMUDriverPtr driver)
{
    int ret = QEMU_SAVE_FORMAT_RAW;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    /*
     * We reuse "save" flag for "dump" here. Then, we can support the same
     * format in "save" and "dump".
     */
    if (cfg->dumpImageFormat) {
        ret = qemuSaveCompressionTypeFromString(cfg->dumpImageFormat);
        /* Use "raw" as the format if the specified format is not valid,
         * or the compress program is not available.
         */
        if (ret < 0) {
            VIR_WARN("%s", _("Invalid dump image format specified in "
                             "configuration file, using raw"));
            ret = QEMU_SAVE_FORMAT_RAW;
            goto cleanup;
        }
        if (!qemuCompressProgramAvailable(ret)) {
            VIR_WARN("%s", _("Compression program for dump image format "
                             "in configuration file isn't available, "
                             "using raw"));
            ret = QEMU_SAVE_FORMAT_RAW;
            goto cleanup;
        }
    }
 cleanup:
    virObjectUnref(cfg);
    return ret;
}


static int
qemuDomainCoreDumpWithFormat(virDomainPtr dom,
                             const char *path,
                             unsigned int dumpformat,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    bool resume = false, paused = false;
    int ret = -1;
    virObjectEventPtr event = NULL;

    virCheckFlags(VIR_DUMP_LIVE | VIR_DUMP_CRASH |
                  VIR_DUMP_BYPASS_CACHE | VIR_DUMP_RESET |
                  VIR_DUMP_MEMORY_ONLY, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainCoreDumpWithFormatEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginAsyncJob(driver, vm,
                                   QEMU_ASYNC_JOB_DUMP) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    /* Migrate will always stop the VM, so the resume condition is
       independent of whether the stop command is issued.  */
    resume = virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING;

    /* Pause domain for non-live dump */
    if (!(flags & VIR_DUMP_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_DUMP,
                                QEMU_ASYNC_JOB_DUMP) < 0)
            goto endjob;
        paused = true;

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto endjob;
        }
    }

    ret = doCoreDump(driver, vm, path, getCompressionType(driver), flags,
                     dumpformat);
    if (ret < 0)
        goto endjob;

    paused = true;

 endjob:
    if ((ret == 0) && (flags & VIR_DUMP_CRASH)) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_CRASHED, 0);
        virDomainAuditStop(vm, "crashed");
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    } else if (((resume && paused) || (flags & VIR_DUMP_RESET)) &&
               virDomainObjIsActive(vm)) {
        if ((ret == 0) && (flags & VIR_DUMP_RESET)) {
            priv =  vm->privateData;
            qemuDomainObjEnterMonitor(driver, vm);
            ret = qemuMonitorSystemReset(priv->mon);
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                ret = -1;
        }

        if (resume && virDomainObjIsActive(vm)) {
            if (qemuProcessStartCPUs(driver, vm, dom->conn,
                                     VIR_DOMAIN_RUNNING_UNPAUSED,
                                     QEMU_ASYNC_JOB_DUMP) < 0) {
                event = virDomainEventLifecycleNewFromObj(vm,
                                                          VIR_DOMAIN_EVENT_SUSPENDED,
                                                          VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
                if (virGetLastError() == NULL)
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   "%s", _("resuming after dump failed"));
            }
        }
    }

    qemuDomainObjEndAsyncJob(driver, vm);
    if (ret == 0 && flags & VIR_DUMP_CRASH)
        qemuDomainRemoveInactive(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    return ret;
}


static int
qemuDomainCoreDump(virDomainPtr dom,
                   const char *path,
                   unsigned int flags)
{
    return qemuDomainCoreDumpWithFormat(dom, path,
                                        VIR_DOMAIN_CORE_DUMP_FORMAT_RAW,
                                        flags);
}


static char *
qemuDomainScreenshot(virDomainPtr dom,
                     virStreamPtr st,
                     unsigned int screen,
                     unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    char *tmp = NULL;
    int tmp_fd = -1;
    char *ret = NULL;
    bool unlink_tmp = false;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainScreenshotEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    /* Well, even if qemu allows multiple graphic cards, heads, whatever,
     * screenshot command does not */
    if (screen) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("currently is supported only taking "
                               "screenshots of screen ID 0"));
        goto endjob;
    }

    if (virAsprintf(&tmp, "%s/qemu.screendump.XXXXXX", cfg->cacheDir) < 0)
        goto endjob;

    if ((tmp_fd = mkostemp(tmp, O_CLOEXEC)) == -1) {
        virReportSystemError(errno, _("mkostemp(\"%s\") failed"), tmp);
        goto endjob;
    }
    unlink_tmp = true;

    virSecurityManagerSetSavedStateLabel(qemu_driver->securityManager, vm->def, tmp);

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorScreendump(priv->mon, tmp) < 0) {
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        goto endjob;
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto endjob;

    if (VIR_CLOSE(tmp_fd) < 0) {
        virReportSystemError(errno, _("unable to close %s"), tmp);
        goto endjob;
    }

    if (virFDStreamOpenFile(st, tmp, 0, 0, O_RDONLY) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("unable to open stream"));
        goto endjob;
    }

    ignore_value(VIR_STRDUP(ret, "image/x-portable-pixmap"));

 endjob:
    VIR_FORCE_CLOSE(tmp_fd);
    if (unlink_tmp)
        unlink(tmp);
    VIR_FREE(tmp);

    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static void processWatchdogEvent(virQEMUDriverPtr driver, virDomainObjPtr vm, int action)
{
    int ret;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    switch (action) {
    case VIR_DOMAIN_WATCHDOG_ACTION_DUMP:
        {
            char *dumpfile;
            unsigned int flags = 0;

            if (virAsprintf(&dumpfile, "%s/%s-%u",
                            cfg->autoDumpPath,
                            vm->def->name,
                            (unsigned int)time(NULL)) < 0)
                goto cleanup;

            if (qemuDomainObjBeginAsyncJob(driver, vm,
                                           QEMU_ASYNC_JOB_DUMP) < 0) {
                VIR_FREE(dumpfile);
                goto cleanup;
            }

            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               "%s", _("domain is not running"));
                VIR_FREE(dumpfile);
                goto endjob;
            }

            flags |= cfg->autoDumpBypassCache ? VIR_DUMP_BYPASS_CACHE: 0;
            ret = doCoreDump(driver, vm, dumpfile,
                             getCompressionType(driver), flags,
                             VIR_DOMAIN_CORE_DUMP_FORMAT_RAW);
            if (ret < 0)
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("Dump failed"));

            ret = qemuProcessStartCPUs(driver, vm, NULL,
                                       VIR_DOMAIN_RUNNING_UNPAUSED,
                                       QEMU_ASYNC_JOB_DUMP);

            if (ret < 0)
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("Resuming after dump failed"));

            VIR_FREE(dumpfile);
        }
        break;
    default:
        goto cleanup;
    }

 endjob:
    qemuDomainObjEndAsyncJob(driver, vm);

 cleanup:
    virObjectUnref(cfg);
}

static int
doCoreDumpToAutoDumpPath(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         unsigned int flags)
{
    int ret = -1;
    char *dumpfile = NULL;
    time_t curtime = time(NULL);
    char timestr[100];
    struct tm time_info;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    localtime_r(&curtime, &time_info);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d-%H:%M:%S", &time_info);

    if (virAsprintf(&dumpfile, "%s/%s-%s",
                    cfg->autoDumpPath,
                    vm->def->name,
                    timestr) < 0)
        goto cleanup;

    if (qemuDomainObjBeginAsyncJob(driver, vm,
                                   QEMU_ASYNC_JOB_DUMP) < 0) {
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    flags |= cfg->autoDumpBypassCache ? VIR_DUMP_BYPASS_CACHE: 0;
    ret = doCoreDump(driver, vm, dumpfile,
                     getCompressionType(driver), flags,
                     VIR_DOMAIN_CORE_DUMP_FORMAT_RAW);
    if (ret < 0)
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("Dump failed"));

 endjob:
    qemuDomainObjEndAsyncJob(driver, vm);

 cleanup:
    VIR_FREE(dumpfile);
    virObjectUnref(cfg);
    return ret;
}

static void
processGuestPanicEvent(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int action)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virObjectEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Ignoring GUEST_PANICKED event from inactive domain %s",
                  vm->def->name);
        goto cleanup;
    }

    virDomainObjSetState(vm,
                         VIR_DOMAIN_CRASHED,
                         VIR_DOMAIN_CRASHED_PANICKED);

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_CRASHED,
                                     VIR_DOMAIN_EVENT_CRASHED_PANICKED);

    qemuDomainEventQueue(driver, event);

    if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
        VIR_WARN("Unable to release lease on %s", vm->def->name);
    VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

    switch (action) {
    case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_DESTROY:
        if (doCoreDumpToAutoDumpPath(driver, vm, VIR_DUMP_MEMORY_ONLY) < 0)
            goto cleanup;
        /* fall through */

    case VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY:
        priv->beingDestroyed = true;

        if (qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_FORCE) < 0) {
            priv->beingDestroyed = false;
            goto cleanup;
        }

        priv->beingDestroyed = false;

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is not running"));
            goto cleanup;
        }

        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_CRASHED, 0);
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);

        qemuDomainEventQueue(driver, event);

        virDomainAuditStop(vm, "destroyed");

        qemuDomainRemoveInactive(driver, vm);
        break;

    case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_RESTART:
        if (doCoreDumpToAutoDumpPath(driver, vm, VIR_DUMP_MEMORY_ONLY) < 0)
            goto cleanup;
        /* fall through */

    case VIR_DOMAIN_LIFECYCLE_CRASH_RESTART:
        qemuDomainSetFakeReboot(driver, vm, true);
        qemuProcessShutdownOrReboot(driver, vm);
        break;

    case VIR_DOMAIN_LIFECYCLE_CRASH_PRESERVE:
        break;

    default:
        break;
    }

 cleanup:
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
        VIR_WARN("Unable to save status on vm %s after state change",
                 vm->def->name);
     }

    virObjectUnref(cfg);
}


static void
processDeviceDeletedEvent(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          char *devAlias)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainDeviceDef dev;

    VIR_DEBUG("Removing device %s from domain %p %s",
              devAlias, vm, vm->def->name);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Domain is not running");
        goto endjob;
    }

    if (virDomainDefFindDevice(vm->def, devAlias, &dev, true) < 0)
        goto endjob;

    if (qemuDomainRemoveDevice(driver, vm, &dev) < 0)
        goto endjob;

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        VIR_WARN("unable to save domain status after removing device %s",
                 devAlias);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(devAlias);
    virObjectUnref(cfg);
}


static void
syncNicRxFilterMacAddr(char *ifname, virNetDevRxFilterPtr guestFilter,
                       virNetDevRxFilterPtr hostFilter)
{
    char newMacStr[VIR_MAC_STRING_BUFLEN];

    if (virMacAddrCmp(&hostFilter->mac, &guestFilter->mac)) {
        virMacAddrFormat(&guestFilter->mac, newMacStr);

        /* set new MAC address from guest to associated macvtap device */
        if (virNetDevSetMAC(ifname, &guestFilter->mac) < 0) {
            VIR_WARN("Couldn't set new MAC address %s to device %s "
                     "while responding to NIC_RX_FILTER_CHANGED",
                     newMacStr, ifname);
        } else {
            VIR_DEBUG("device %s MAC address set to %s", ifname, newMacStr);
        }
    }
}


static void
syncNicRxFilterGuestMulticast(char *ifname, virNetDevRxFilterPtr guestFilter,
                              virNetDevRxFilterPtr hostFilter)
{
    size_t i, j;
    bool found;
    char macstr[VIR_MAC_STRING_BUFLEN];

    for (i = 0; i < guestFilter->multicast.nTable; i++) {
        found = false;

        for (j = 0; j < hostFilter->multicast.nTable; j++) {
            if (virMacAddrCmp(&guestFilter->multicast.table[i],
                              &hostFilter->multicast.table[j]) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            virMacAddrFormat(&guestFilter->multicast.table[i], macstr);

            if (virNetDevAddMulti(ifname, &guestFilter->multicast.table[i]) < 0) {
                VIR_WARN("Couldn't add new multicast MAC address %s to "
                         "device %s while responding to NIC_RX_FILTER_CHANGED",
                         macstr, ifname);
            } else {
                VIR_DEBUG("Added multicast MAC %s to %s interface",
                          macstr, ifname);
            }
        }
    }
}


static void
syncNicRxFilterHostMulticast(char *ifname, virNetDevRxFilterPtr guestFilter,
                             virNetDevRxFilterPtr hostFilter)
{
    size_t i, j;
    bool found;
    char macstr[VIR_MAC_STRING_BUFLEN];

    for (i = 0; i < hostFilter->multicast.nTable; i++) {
        found = false;

        for (j = 0; j < guestFilter->multicast.nTable; j++) {
            if (virMacAddrCmp(&hostFilter->multicast.table[i],
                              &guestFilter->multicast.table[j]) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            virMacAddrFormat(&hostFilter->multicast.table[i], macstr);

            if (virNetDevDelMulti(ifname, &hostFilter->multicast.table[i]) < 0) {
                VIR_WARN("Couldn't delete multicast MAC address %s from "
                         "device %s while responding to NIC_RX_FILTER_CHANGED",
                         macstr, ifname);
            } else {
                VIR_DEBUG("Deleted multicast MAC %s from %s interface",
                          macstr, ifname);
            }
        }
    }
}


static void
syncNicRxFilterPromiscMode(char *ifname,
                           virNetDevRxFilterPtr guestFilter,
                           virNetDevRxFilterPtr hostFilter)
{
    bool promisc;
    bool setpromisc = false;

    /* Set macvtap promisc mode to true if the guest has vlans defined */
    /* or synchronize the macvtap promisc mode if different from guest */
    if (guestFilter->vlan.nTable > 0) {
        if (!hostFilter->promiscuous) {
            setpromisc = true;
            promisc = true;
        }
    } else if (hostFilter->promiscuous != guestFilter->promiscuous) {
        setpromisc = true;
        promisc = guestFilter->promiscuous;
    }

    if (setpromisc) {
        if (virNetDevSetPromiscuous(ifname, promisc) < 0) {
            VIR_WARN("Couldn't set PROMISC flag to %s for device %s "
                     "while responding to NIC_RX_FILTER_CHANGED",
                     promisc ? "true" : "false", ifname);
        }
    }
}


static void
syncNicRxFilterMultiMode(char *ifname, virNetDevRxFilterPtr guestFilter,
                         virNetDevRxFilterPtr hostFilter)
{
    if (hostFilter->multicast.mode != guestFilter->multicast.mode) {
        switch (guestFilter->multicast.mode) {
            case VIR_NETDEV_RX_FILTER_MODE_ALL:
                if (virNetDevSetRcvAllMulti(ifname, true)) {

                    VIR_WARN("Couldn't set allmulticast flag to 'on' for "
                             "device %s while responding to "
                             "NIC_RX_FILTER_CHANGED", ifname);
                }
                break;

            case VIR_NETDEV_RX_FILTER_MODE_NORMAL:
                if (virNetDevSetRcvMulti(ifname, true)) {

                    VIR_WARN("Couldn't set multicast flag to 'on' for "
                             "device %s while responding to "
                             "NIC_RX_FILTER_CHANGED", ifname);
                }

                if (virNetDevSetRcvAllMulti(ifname, false)) {
                    VIR_WARN("Couldn't set allmulticast flag to 'off' for "
                             "device %s while responding to "
                             "NIC_RX_FILTER_CHANGED", ifname);
                }
                break;

            case VIR_NETDEV_RX_FILTER_MODE_NONE:
                if (virNetDevSetRcvAllMulti(ifname, false)) {
                    VIR_WARN("Couldn't set allmulticast flag to 'off' for "
                             "device %s while responding to "
                             "NIC_RX_FILTER_CHANGED", ifname);
                }

                if (virNetDevSetRcvMulti(ifname, false)) {
                    VIR_WARN("Couldn't set multicast flag to 'off' for "
                             "device %s while responding to "
                             "NIC_RX_FILTER_CHANGED",
                             ifname);
                }
                break;
        }
    }
}


static void
syncNicRxFilterDeviceOptions(char *ifname, virNetDevRxFilterPtr guestFilter,
                           virNetDevRxFilterPtr hostFilter)
{
    syncNicRxFilterPromiscMode(ifname, guestFilter, hostFilter);
    syncNicRxFilterMultiMode(ifname, guestFilter, hostFilter);
}


static void
syncNicRxFilterMulticast(char *ifname,
                         virNetDevRxFilterPtr guestFilter,
                         virNetDevRxFilterPtr hostFilter)
{
    syncNicRxFilterGuestMulticast(ifname, guestFilter, hostFilter);
    syncNicRxFilterHostMulticast(ifname, guestFilter, hostFilter);
}

static void
processNicRxFilterChangedEvent(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               char *devAlias)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDeviceDef dev;
    virDomainNetDefPtr def;
    virNetDevRxFilterPtr guestFilter = NULL;
    virNetDevRxFilterPtr hostFilter = NULL;
    int ret;

    VIR_DEBUG("Received NIC_RX_FILTER_CHANGED event for device %s "
              "from domain %p %s",
              devAlias, vm, vm->def->name);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Domain is not running");
        goto endjob;
    }

    if (virDomainDefFindDevice(vm->def, devAlias, &dev, true) < 0) {
        VIR_WARN("NIC_RX_FILTER_CHANGED event received for "
                 "non-existent device %s in domain %s",
                 devAlias, vm->def->name);
        goto endjob;
    }
    if (dev.type != VIR_DOMAIN_DEVICE_NET) {
        VIR_WARN("NIC_RX_FILTER_CHANGED event received for "
                 "non-network device %s in domain %s",
                 devAlias, vm->def->name);
        goto endjob;
    }
    def = dev.data.net;

    if (!virDomainNetGetActualTrustGuestRxFilters(def)) {
        VIR_DEBUG("ignore NIC_RX_FILTER_CHANGED event for network "
                  "device %s in domain %s",
                  def->info.alias, vm->def->name);
        /* not sending "query-rx-filter" will also suppress any
         * further NIC_RX_FILTER_CHANGED events for this device
         */
        goto endjob;
    }

    /* handle the event - send query-rx-filter and respond to it. */

    VIR_DEBUG("process NIC_RX_FILTER_CHANGED event for network "
              "device %s in domain %s", def->info.alias, vm->def->name);

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorQueryRxFilter(priv->mon, devAlias, &guestFilter);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0)
        goto endjob;

    if (virDomainNetGetActualType(def) == VIR_DOMAIN_NET_TYPE_DIRECT) {

        if (virNetDevGetRxFilter(def->ifname, &hostFilter)) {
            VIR_WARN("Couldn't get current RX filter for device %s "
                     "while responding to NIC_RX_FILTER_CHANGED",
                     def->ifname);
            goto endjob;
        }

        /* For macvtap connections, set the following macvtap network device
         * attributes to match those of the guest network device:
         * - MAC address
         * - Multicast MAC address table
         * - Device options:
         *   - PROMISC
         *   - MULTICAST
         *   - ALLMULTI
         */
        syncNicRxFilterMacAddr(def->ifname, guestFilter, hostFilter);
        syncNicRxFilterMulticast(def->ifname, guestFilter, hostFilter);
        syncNicRxFilterDeviceOptions(def->ifname, guestFilter, hostFilter);
    }

    if (virDomainNetGetActualType(def) == VIR_DOMAIN_NET_TYPE_NETWORK) {
        const char *brname = virDomainNetGetActualBridgeName(def);

        /* For libivrt network connections, set the following TUN/TAP network
         * device attributes to match those of the guest network device:
         * - QoS filters (which are based on MAC address)
         */
        if (virDomainNetGetActualBandwidth(def) &&
            def->data.network.actual &&
            virNetDevBandwidthUpdateFilter(brname, &guestFilter->mac,
                                           def->data.network.actual->class_id) < 0)
            goto endjob;
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virNetDevRxFilterFree(hostFilter);
    virNetDevRxFilterFree(guestFilter);
    VIR_FREE(devAlias);
    virObjectUnref(cfg);
}


static void
processSerialChangedEvent(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          char *devAlias,
                          bool connected)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainChrDeviceState newstate;
    virObjectEventPtr event = NULL;
    virDomainDeviceDef dev;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if (connected)
        newstate = VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED;
    else
        newstate = VIR_DOMAIN_CHR_DEVICE_STATE_DISCONNECTED;

    VIR_DEBUG("Changing serial port state %s in domain %p %s",
              devAlias, vm, vm->def->name);

    if (newstate == VIR_DOMAIN_CHR_DEVICE_STATE_DISCONNECTED &&
        virDomainObjIsActive(vm) && priv->agent) {
        /* peek into the domain definition to find the channel */
        if (virDomainDefFindDevice(vm->def, devAlias, &dev, true) == 0 &&
            dev.type == VIR_DOMAIN_DEVICE_CHR &&
            dev.data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
            dev.data.chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
            STREQ_NULLABLE(dev.data.chr->target.name, "org.qemu.guest_agent.0"))
            /* Close agent monitor early, so that other threads
             * waiting for the agent to reply can finish and our
             * job we acquire below can succeed. */
            qemuAgentNotifyClose(priv->agent);

        /* now discard the data, since it may possibly change once we unlock
         * while entering the job */
        memset(&dev, 0, sizeof(dev));
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Domain is not running");
        goto endjob;
    }

    if (virDomainDefFindDevice(vm->def, devAlias, &dev, true) < 0)
        goto endjob;

    /* we care only about certain devices */
    if (dev.type != VIR_DOMAIN_DEVICE_CHR ||
        dev.data.chr->deviceType != VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL ||
        dev.data.chr->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO)
        goto endjob;

    if (STREQ_NULLABLE(dev.data.chr->target.name, "org.qemu.guest_agent.0")) {
        if (newstate == VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED) {
            if (!priv->agent) {
                if ((rc = qemuConnectAgent(driver, vm)) == -2)
                    goto endjob;

                if (rc < 0)
                    priv->agentError = true;
            }
        } else {
            if (priv->agent) {
                qemuAgentClose(priv->agent);
                priv->agent = NULL;
                priv->agentError = false;
            }
        }

        event = virDomainEventAgentLifecycleNewFromObj(vm, newstate,
                                                       VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_CHANNEL);
        qemuDomainEventQueue(driver, event);
    }

    dev.data.chr->state = newstate;

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        VIR_WARN("unable to save status of domain %s after updating state of "
                 "channel %s", vm->def->name, devAlias);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(devAlias);
    virObjectUnref(cfg);

}


static void
processBlockJobEvent(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     char *diskAlias,
                     int type,
                     int status)
{
    virDomainDiskDefPtr disk;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Domain is not running");
        goto endjob;
    }

    if ((disk = qemuProcessFindDomainDiskByAlias(vm, diskAlias)))
        qemuBlockJobEventProcess(driver, vm, disk, type, status);

 endjob:
    qemuDomainObjEndJob(driver, vm);
 cleanup:
    VIR_FREE(diskAlias);
}


static void qemuProcessEventHandler(void *data, void *opaque)
{
    struct qemuProcessEvent *processEvent = data;
    virDomainObjPtr vm = processEvent->vm;
    virQEMUDriverPtr driver = opaque;

    VIR_DEBUG("vm=%p", vm);

    virObjectLock(vm);

    switch (processEvent->eventType) {
    case QEMU_PROCESS_EVENT_WATCHDOG:
        processWatchdogEvent(driver, vm, processEvent->action);
        break;
    case QEMU_PROCESS_EVENT_GUESTPANIC:
        processGuestPanicEvent(driver, vm, processEvent->action);
        break;
    case QEMU_PROCESS_EVENT_DEVICE_DELETED:
        processDeviceDeletedEvent(driver, vm, processEvent->data);
        break;
    case QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED:
        processNicRxFilterChangedEvent(driver, vm, processEvent->data);
        break;
    case QEMU_PROCESS_EVENT_SERIAL_CHANGED:
        processSerialChangedEvent(driver, vm, processEvent->data,
                                  processEvent->action);
        break;
    case QEMU_PROCESS_EVENT_BLOCK_JOB:
        processBlockJobEvent(driver, vm,
                             processEvent->data,
                             processEvent->action,
                             processEvent->status);
        break;
    case QEMU_PROCESS_EVENT_LAST:
        break;
    }

    virDomainObjEndAPI(&vm);
    VIR_FREE(processEvent);
}

static virCgroupPtr
qemuDomainAddCgroupForThread(virCgroupPtr cgroup,
                             virCgroupThreadName nameval,
                             int idx,
                             char *mem_mask,
                             pid_t pid)
{
    virCgroupPtr new_cgroup = NULL;
    int rv = -1;

    /* Create cgroup */
    if (virCgroupNewThread(cgroup, nameval, idx, true, &new_cgroup) < 0)
        return NULL;

    if (mem_mask &&
        virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPUSET) &&
        virCgroupSetCpusetMems(new_cgroup, mem_mask) < 0)
        goto error;

    /* Add pid/thread to the cgroup */
    rv = virCgroupAddTask(new_cgroup, pid);
    if (rv < 0) {
        virCgroupRemove(new_cgroup);
        goto error;
    }

    return new_cgroup;

 error:
    virCgroupFree(&new_cgroup);
    return NULL;
}

static int
qemuDomainHotplugAddPin(virBitmapPtr cpumask,
                        int idx,
                        virDomainPinDefPtr **pindef_list,
                        size_t *npin)
{
    int ret = -1;
    virDomainPinDefPtr pindef = NULL;

    if (VIR_ALLOC(pindef) < 0)
        goto cleanup;

    if (!(pindef->cpumask = virBitmapNewCopy(cpumask))) {
        VIR_FREE(pindef);
        goto cleanup;
    }
    pindef->id = idx;
    if (VIR_APPEND_ELEMENT_COPY(*pindef_list, *npin, pindef) < 0) {
        virBitmapFree(pindef->cpumask);
        VIR_FREE(pindef);
        goto cleanup;
    }
    ret = 0;

 cleanup:
    return ret;
}

static int
qemuDomainHotplugPinThread(virBitmapPtr cpumask,
                           int idx,
                           pid_t pid,
                           virCgroupPtr cgroup)
{
    int ret = -1;

    if (cgroup &&
        virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
        if (qemuSetupCgroupCpusetCpus(cgroup, cpumask) < 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("failed to set cpuset.cpus in cgroup for id %d"),
                           idx);
            goto cleanup;
        }
    } else {
        if (virProcessSetAffinity(pid, cpumask) < 0) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to set cpu affinity for id %d"),
                           idx);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    return ret;
}

static int
qemuDomainDelCgroupForThread(virCgroupPtr cgroup,
                             virCgroupThreadName nameval,
                             int idx)
{
    virCgroupPtr new_cgroup = NULL;

    if (cgroup) {
        if (virCgroupNewThread(cgroup, nameval, idx, false, &new_cgroup) < 0)
            return -1;

        /* Remove the offlined cgroup */
        virCgroupRemove(new_cgroup);
        virCgroupFree(&new_cgroup);
    }

    return 0;
}

static int
qemuDomainHotplugAddVcpu(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         unsigned int vcpu)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int rc;
    int oldvcpus = virDomainDefGetVcpus(vm->def);
    pid_t *cpupids = NULL;
    int ncpupids = 0;
    virCgroupPtr cgroup_vcpu = NULL;
    char *mem_mask = NULL;
    virDomainNumatuneMemMode mem_mode;

    qemuDomainObjEnterMonitor(driver, vm);

    rc = qemuMonitorSetCPU(priv->mon, vcpu, true);

    if (rc == 0)
        ncpupids = qemuMonitorGetCPUInfo(priv->mon, &cpupids);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    virDomainAuditVcpu(vm, oldvcpus, oldvcpus + 1, "update", rc == 0);

    if (rc < 0)
        goto cleanup;

    ignore_value(virDomainDefSetVcpus(vm->def, oldvcpus + 1));

    if (ncpupids < 0)
        goto cleanup;

    /* failure to re-detect vCPU pids after hotplug due to lack of support was
     * historically deemed not fatal. We need to skip the rest of the steps though. */
    if (ncpupids == 0) {
        ret = 0;
        goto cleanup;
    }

    if (ncpupids != oldvcpus + 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("got wrong number of vCPU pids from QEMU monitor. "
                         "got %d, wanted %d"),
                       ncpupids, oldvcpus + 1);
        goto cleanup;
    }

    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
        mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
        virDomainNumatuneMaybeFormatNodeset(vm->def->numa,
                                            priv->autoNodeset,
                                            &mem_mask, -1) < 0)
        goto cleanup;

    if (priv->cgroup) {
        cgroup_vcpu =
            qemuDomainAddCgroupForThread(priv->cgroup,
                                         VIR_CGROUP_THREAD_VCPU,
                                         vcpu, mem_mask,
                                         cpupids[vcpu]);
        if (!cgroup_vcpu)
            goto cleanup;
    }

    /* Inherit def->cpuset */
    if (vm->def->cpumask) {
        if (qemuDomainHotplugAddPin(vm->def->cpumask, vcpu,
                                    &vm->def->cputune.vcpupin,
                                    &vm->def->cputune.nvcpupin) < 0)
            goto cleanup;

        if (qemuDomainHotplugPinThread(vm->def->cpumask, vcpu, cpupids[vcpu],
                                       cgroup_vcpu) < 0) {
            goto cleanup;
        }
    }

    if (qemuProcessSetSchedParams(vcpu, cpupids[vcpu],
                                  vm->def->cputune.nvcpusched,
                                  vm->def->cputune.vcpusched) < 0)
        goto cleanup;

    priv->nvcpupids = ncpupids;
    VIR_FREE(priv->vcpupids);
    priv->vcpupids = cpupids;
    cpupids = NULL;

    ret = 0;

 cleanup:
    VIR_FREE(cpupids);
    VIR_FREE(mem_mask);
    virCgroupFree(&cgroup_vcpu);
    return ret;
}


static int
qemuDomainHotplugDelVcpu(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         unsigned int vcpu)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int rc;
    int oldvcpus = virDomainDefGetVcpus(vm->def);
    pid_t *cpupids = NULL;
    int ncpupids = 0;

    qemuDomainObjEnterMonitor(driver, vm);

    rc = qemuMonitorSetCPU(priv->mon, vcpu, false);

    if (rc == 0)
        ncpupids = qemuMonitorGetCPUInfo(priv->mon, &cpupids);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    virDomainAuditVcpu(vm, oldvcpus, oldvcpus - 1, "update",
                       rc == 0 && ncpupids == oldvcpus -1);

    if (rc < 0 || ncpupids < 0)
        goto cleanup;

    /* check if hotunplug has failed */
    if (ncpupids != oldvcpus - 1) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("qemu didn't unplug vCPU '%u' properly"), vcpu);
        goto cleanup;
    }

    ignore_value(virDomainDefSetVcpus(vm->def, oldvcpus - 1));

    if (qemuDomainDelCgroupForThread(priv->cgroup,
                                     VIR_CGROUP_THREAD_VCPU, vcpu) < 0)
        goto cleanup;

    /* Free vcpupin setting */
    virDomainPinDel(&vm->def->cputune.vcpupin,
                    &vm->def->cputune.nvcpupin,
                    vcpu);

    priv->nvcpupids = ncpupids;
    VIR_FREE(priv->vcpupids);
    priv->vcpupids = cpupids;
    cpupids = NULL;

    ret = 0;

 cleanup:
    VIR_FREE(cpupids);
    return ret;
}


static int
qemuDomainSetVcpusAgent(virDomainObjPtr vm,
                        unsigned int nvcpus)
{
    qemuAgentCPUInfoPtr cpuinfo = NULL;
    int ncpuinfo;
    int ret = -1;

    if (!qemuDomainAgentAvailable(vm, true))
        goto cleanup;

    if (nvcpus > virDomainDefGetVcpus(vm->def)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpu count is greater than the count "
                         "of enabled vcpus in the domain: %d > %d"),
                       nvcpus, virDomainDefGetVcpus(vm->def));
        goto cleanup;
    }

    qemuDomainObjEnterAgent(vm);
    ncpuinfo = qemuAgentGetVCPUs(qemuDomainGetAgent(vm), &cpuinfo);
    qemuDomainObjExitAgent(vm);

    if (ncpuinfo < 0)
        goto cleanup;

    if (qemuAgentUpdateCPUInfo(nvcpus, cpuinfo, ncpuinfo) < 0)
        goto cleanup;

    if (!qemuDomainAgentAvailable(vm, true))
        goto cleanup;

    qemuDomainObjEnterAgent(vm);
    ret = qemuAgentSetVCPUs(qemuDomainGetAgent(vm), cpuinfo, ncpuinfo);
    qemuDomainObjExitAgent(vm);

    if (ret < 0)
        goto cleanup;

    if (ret < ncpuinfo) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to set state of cpu %d via guest agent"),
                       cpuinfo[ret-1].id);
        ret = -1;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cpuinfo);

    return ret;
}


static int
qemuDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                        unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1;
    unsigned int maxvcpus = 0;
    virQEMUDriverConfigPtr cfg = NULL;
    qemuDomainObjPrivatePtr priv;
    size_t i;
    virCgroupPtr cgroup_temp = NULL;
    char *mem_mask = NULL;
    char *all_nodes_str = NULL;
    virBitmapPtr all_nodes = NULL;
    virErrorPtr err = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM |
                  VIR_DOMAIN_VCPU_GUEST, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_VCPU_GUEST) {
        ret = qemuDomainSetVcpusAgent(vm, nvcpus);
        goto endjob;
    }

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (def && virNumaIsAvailable() &&
        virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                               false, &cgroup_temp) < 0)
            goto endjob;

        if (!(all_nodes = virNumaGetHostNodeset()))
            goto endjob;

        if (!(all_nodes_str = virBitmapFormat(all_nodes)))
            goto endjob;

        if (virCgroupGetCpusetMems(cgroup_temp, &mem_mask) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, all_nodes_str) < 0)
            goto endjob;
    }

    if (def)
        maxvcpus = virDomainDefGetVcpusMax(def);
    if (persistentDef) {
        if (!maxvcpus || maxvcpus > virDomainDefGetVcpusMax(persistentDef))
            maxvcpus = virDomainDefGetVcpusMax(persistentDef);
    }
    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM) && nvcpus > maxvcpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable"
                         " vcpus for the domain: %d > %d"),
                       nvcpus, maxvcpus);
        goto endjob;
    }

    if (def) {
        if (nvcpus > virDomainDefGetVcpus(def)) {
            for (i = virDomainDefGetVcpus(def); i < nvcpus; i++) {
                if (qemuDomainHotplugAddVcpu(driver, vm, i) < 0)
                    goto endjob;
            }
        } else {
            for (i = virDomainDefGetVcpus(def) - 1; i >= nvcpus; i--) {
                if (qemuDomainHotplugDelVcpu(driver, vm, i) < 0)
                    goto endjob;
            }
        }

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;
    }

    if (persistentDef) {
        /* remove vcpupin entries for vcpus that were unplugged */
        if (nvcpus < virDomainDefGetVcpus(persistentDef)) {
            for (i = virDomainDefGetVcpus(persistentDef) - 1; i >= nvcpus; i--)
                virDomainPinDel(&persistentDef->cputune.vcpupin,
                                &persistentDef->cputune.nvcpupin,
                                i);
        }

        if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
            if (virDomainDefSetVcpusMax(persistentDef, nvcpus) < 0)
                goto endjob;
        } else {
            if (virDomainDefSetVcpus(persistentDef, nvcpus) < 0)
                goto endjob;
        }

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            goto endjob;
    }

    ret = 0;

 endjob:
    if (mem_mask) {
        err = virSaveLastError();
        virCgroupSetCpusetMems(cgroup_temp, mem_mask);
        virSetError(err);
        virFreeError(err);
    }

    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    VIR_FREE(mem_mask);
    VIR_FREE(all_nodes_str);
    virBitmapFree(all_nodes);
    virCgroupFree(&cgroup_temp);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return qemuDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}


static int
qemuDomainPinVcpuFlags(virDomainPtr dom,
                       unsigned int vcpu,
                       unsigned char *cpumap,
                       int maplen,
                       unsigned int flags)
{

    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    virCgroupPtr cgroup_vcpu = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    size_t newVcpuPinNum = 0;
    virDomainPinDefPtr *newVcpuPin = NULL;
    virBitmapPtr pcpumap = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virObjectEventPtr event = NULL;
    char paramField[VIR_TYPED_PARAM_FIELD_LENGTH] = "";
    char *str = NULL;
    virTypedParameterPtr eventParams = NULL;
    int eventNparams = 0;
    int eventMaxparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinVcpuFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    priv = vm->privateData;

    if (def && vcpu >= virDomainDefGetVcpus(def)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("vcpu %d is out of range of live cpu count %d"),
                       vcpu, virDomainDefGetVcpus(def));
        goto endjob;
    }

    if (persistentDef && vcpu >= virDomainDefGetVcpus(persistentDef)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("vcpu %d is out of range of persistent cpu count %d"),
                       vcpu, virDomainDefGetVcpus(persistentDef));
        goto endjob;
    }

    if (!(pcpumap = virBitmapNewData(cpumap, maplen)))
        goto endjob;

    if (virBitmapIsAllClear(pcpumap)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Empty cpu list for pinning"));
        goto endjob;
    }

    if (def) {
        if (!qemuDomainHasVcpuPids(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cpu affinity is not supported"));
            goto endjob;
        }

        if (def->cputune.vcpupin) {
            newVcpuPin = virDomainPinDefCopy(def->cputune.vcpupin,
                                             def->cputune.nvcpupin);
            if (!newVcpuPin)
                goto endjob;

            newVcpuPinNum = def->cputune.nvcpupin;
        } else {
            if (VIR_ALLOC(newVcpuPin) < 0)
                goto endjob;
            newVcpuPinNum = 0;
        }

        if (virDomainPinAdd(&newVcpuPin, &newVcpuPinNum,
                            cpumap, maplen, vcpu) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to update vcpupin"));
            goto endjob;
        }

        /* Configure the corresponding cpuset cgroup before set affinity. */
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, vcpu,
                                   false, &cgroup_vcpu) < 0)
                goto endjob;
            if (qemuSetupCgroupCpusetCpus(cgroup_vcpu, pcpumap) < 0) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("failed to set cpuset.cpus in cgroup"
                                 " for vcpu %d"), vcpu);
                goto endjob;
            }
        } else {
            if (virProcessSetAffinity(qemuDomainGetVcpuPid(vm, vcpu),
                                      pcpumap) < 0) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("failed to set cpu affinity for vcpu %d"),
                               vcpu);
                goto endjob;
            }
        }

        if (def->cputune.vcpupin)
            virDomainPinDefArrayFree(def->cputune.vcpupin,
                                     def->cputune.nvcpupin);

        def->cputune.vcpupin = newVcpuPin;
        def->cputune.nvcpupin = newVcpuPinNum;
        newVcpuPin = NULL;

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;

        if (snprintf(paramField, VIR_TYPED_PARAM_FIELD_LENGTH,
                     VIR_DOMAIN_TUNABLE_CPU_VCPUPIN, vcpu) < 0) {
            goto endjob;
        }

        str = virBitmapFormat(pcpumap);
        if (virTypedParamsAddString(&eventParams, &eventNparams,
                                    &eventMaxparams, paramField, str) < 0)
            goto endjob;

        event = virDomainEventTunableNewFromDom(dom, eventParams, eventNparams);
    }

    if (persistentDef) {
        if (!persistentDef->cputune.vcpupin) {
            if (VIR_ALLOC(persistentDef->cputune.vcpupin) < 0)
                goto endjob;
            persistentDef->cputune.nvcpupin = 0;
        }
        if (virDomainPinAdd(&persistentDef->cputune.vcpupin,
                            &persistentDef->cputune.nvcpupin,
                            cpumap,
                            maplen,
                            vcpu) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to update or add vcpupin xml of "
                             "a persistent domain"));
            goto endjob;
        }

        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    if (newVcpuPin)
        virDomainPinDefArrayFree(newVcpuPin, newVcpuPinNum);
    if (cgroup_vcpu)
        virCgroupFree(&cgroup_vcpu);
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    VIR_FREE(str);
    virBitmapFree(pcpumap);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainPinVcpu(virDomainPtr dom,
                   unsigned int vcpu,
                   unsigned char *cpumap,
                   int maplen)
{
    return qemuDomainPinVcpuFlags(dom, vcpu, cpumap, maplen,
                                  VIR_DOMAIN_AFFECT_LIVE);
}

static int
qemuDomainGetVcpuPinInfo(virDomainPtr dom,
                         int ncpumaps,
                         unsigned char *cpumaps,
                         int maplen,
                         unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    int ret = -1;
    int hostcpus, vcpu;
    virBitmapPtr allcpumap = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpuPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if ((hostcpus = nodeGetCPUCount(NULL)) < 0)
        goto cleanup;

    if (!(allcpumap = virBitmapNew(hostcpus)))
        goto cleanup;

    virBitmapSetAll(allcpumap);
    priv = vm->privateData;

    /* Clamp to actual number of vcpus */
    if (ncpumaps > virDomainDefGetVcpus(def))
        ncpumaps = virDomainDefGetVcpus(def);

    if (ncpumaps < 1)
        goto cleanup;

    for (vcpu = 0; vcpu < ncpumaps; vcpu++) {
        virDomainPinDefPtr pininfo;
        virBitmapPtr bitmap = NULL;

        pininfo = virDomainPinFind(def->cputune.vcpupin,
                                   def->cputune.nvcpupin,
                                   vcpu);

        if (pininfo && pininfo->cpumask)
            bitmap = pininfo->cpumask;
        else if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
                 priv->autoCpuset)
            bitmap = priv->autoCpuset;
        else
            bitmap = allcpumap;

        virBitmapToDataBuf(bitmap, VIR_GET_CPUMAP(cpumaps, maplen, vcpu), maplen);
    }

    ret = ncpumaps;

 cleanup:
    virBitmapFree(allcpumap);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainPinEmulator(virDomainPtr dom,
                      unsigned char *cpumap,
                      int maplen,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virCgroupPtr cgroup_emulator = NULL;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    virBitmapPtr pcpumap = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virObjectEventPtr event = NULL;
    char *str = NULL;
    virTypedParameterPtr eventParams = NULL;
    int eventNparams = 0;
    int eventMaxparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinEmulatorEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Changing affinity for emulator thread dynamically "
                         "is not allowed when CPU placement is 'auto'"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    priv = vm->privateData;

    if (!(pcpumap = virBitmapNewData(cpumap, maplen)))
        goto endjob;

    if (virBitmapIsAllClear(pcpumap)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Empty cpu list for pinning"));
        goto endjob;
    }

    if (def) {
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR,
                                   0, false, &cgroup_emulator) < 0)
                goto endjob;

            if (qemuSetupCgroupCpusetCpus(cgroup_emulator, pcpumap) < 0) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("failed to set cpuset.cpus in cgroup"
                                 " for emulator threads"));
                goto endjob;
            }
        } else {
            if (virProcessSetAffinity(vm->pid, pcpumap) < 0) {
                virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                               _("failed to set cpu affinity for "
                                 "emulator thread"));
                goto endjob;
            }
        }

        virBitmapFree(def->cputune.emulatorpin);
        def->cputune.emulatorpin = NULL;

        if (!(def->cputune.emulatorpin = virBitmapNewCopy(pcpumap)))
            goto endjob;

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;

        str = virBitmapFormat(pcpumap);
        if (virTypedParamsAddString(&eventParams, &eventNparams,
                                    &eventMaxparams,
                                    VIR_DOMAIN_TUNABLE_CPU_EMULATORPIN,
                                    str) < 0)
            goto endjob;

        event = virDomainEventTunableNewFromDom(dom, eventParams, eventNparams);
    }

    if (persistentDef) {
        virBitmapFree(persistentDef->cputune.emulatorpin);
        persistentDef->cputune.emulatorpin = NULL;

        if (!(persistentDef->cputune.emulatorpin = virBitmapNewCopy(pcpumap)))
            goto endjob;

        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    if (cgroup_emulator)
        virCgroupFree(&cgroup_emulator);
    qemuDomainEventQueue(driver, event);
    VIR_FREE(str);
    virBitmapFree(pcpumap);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetEmulatorPinInfo(virDomainPtr dom,
                             unsigned char *cpumaps,
                             int maplen,
                             unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    int ret = -1;
    int hostcpus;
    virBitmapPtr cpumask = NULL;
    virBitmapPtr bitmap = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetEmulatorPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if ((hostcpus = nodeGetCPUCount(NULL)) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (def->cputune.emulatorpin) {
        cpumask = def->cputune.emulatorpin;
    } else if (def->cpumask) {
        cpumask = def->cpumask;
    } else if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
               priv->autoCpuset) {
        cpumask = priv->autoCpuset;
    } else {
        if (!(bitmap = virBitmapNew(hostcpus)))
            goto cleanup;
        virBitmapSetAll(bitmap);
        cpumask = bitmap;
    }

    virBitmapToDataBuf(cpumask, cpumaps, maplen);

    ret = 1;

 cleanup:
    virDomainObjEndAPI(&vm);
    virBitmapFree(bitmap);
    return ret;
}

static int
qemuDomainGetVcpus(virDomainPtr dom,
                   virVcpuInfoPtr info,
                   int maxinfo,
                   unsigned char *cpumaps,
                   int maplen)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpusEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s",
                       _("cannot list vcpu pinning for an inactive domain"));
        goto cleanup;
    }

    ret = qemuDomainHelperGetVcpus(vm, info, maxinfo, cpumaps, maplen);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;
    qemuAgentCPUInfoPtr cpuinfo = NULL;
    int ncpuinfo = -1;
    size_t i;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM |
                  VIR_DOMAIN_VCPU_GUEST, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainGetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if (flags & VIR_DOMAIN_VCPU_GUEST) {
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("vCPU count provided by the guest agent can only be "
                             "requested for live domains"));
            goto cleanup;
        }

        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
            goto cleanup;

        if (!qemuDomainAgentAvailable(vm, true))
            goto endjob;

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain is not running"));
            goto endjob;
        }

        qemuDomainObjEnterAgent(vm);
        ncpuinfo = qemuAgentGetVCPUs(priv->agent, &cpuinfo);
        qemuDomainObjExitAgent(vm);

 endjob:
        qemuDomainObjEndJob(driver, vm);

        if (ncpuinfo < 0)
            goto cleanup;

        if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
            ret = ncpuinfo;
            goto cleanup;
        }

        /* count the online vcpus */
        ret = 0;
        for (i = 0; i < ncpuinfo; i++) {
            if (cpuinfo[i].online)
                ret++;
        }
    } else {
        if (flags & VIR_DOMAIN_VCPU_MAXIMUM)
            ret = virDomainDefGetVcpusMax(def);
        else
            ret = virDomainDefGetVcpus(def);
    }


 cleanup:
    virDomainObjEndAPI(&vm);
    VIR_FREE(cpuinfo);
    return ret;
}

static int
qemuDomainGetMaxVcpus(virDomainPtr dom)
{
    return qemuDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                         VIR_DOMAIN_VCPU_MAXIMUM));
}

static int
qemuDomainGetIOThreadsLive(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainIOThreadInfoPtr **info)
{
    qemuDomainObjPrivatePtr priv;
    qemuMonitorIOThreadInfoPtr *iothreads = NULL;
    virDomainIOThreadInfoPtr *info_ret = NULL;
    int niothreads = 0;
    size_t i;
    int ret = -1;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot list IOThreads for an inactive domain"));
        goto endjob;
    }

    priv = vm->privateData;
    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_OBJECT_IOTHREAD)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IOThreads not supported with this binary"));
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    niothreads = qemuMonitorGetIOThreads(priv->mon, &iothreads);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto endjob;
    if (niothreads < 0)
        goto endjob;

    /* Nothing to do */
    if (niothreads == 0) {
        ret = 0;
        goto endjob;
    }

    if (VIR_ALLOC_N(info_ret, niothreads) < 0)
        goto endjob;

    for (i = 0; i < niothreads; i++) {
        virBitmapPtr map = NULL;

        if (VIR_ALLOC(info_ret[i]) < 0)
            goto endjob;
        info_ret[i]->iothread_id = iothreads[i]->iothread_id;

        if (!(map = virProcessGetAffinity(iothreads[i]->thread_id)))
            goto endjob;

        if (virBitmapToData(map, &info_ret[i]->cpumap,
                            &info_ret[i]->cpumaplen) < 0) {
            virBitmapFree(map);
            goto endjob;
        }
        virBitmapFree(map);
    }

    *info = info_ret;
    info_ret = NULL;
    ret = niothreads;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    if (info_ret) {
        for (i = 0; i < niothreads; i++)
            virDomainIOThreadInfoFree(info_ret[i]);
        VIR_FREE(info_ret);
    }
    if (iothreads) {
        for (i = 0; i < niothreads; i++)
            VIR_FREE(iothreads[i]);
        VIR_FREE(iothreads);
    }

    return ret;
}

static int
qemuDomainGetIOThreadsConfig(virDomainDefPtr targetDef,
                             virDomainIOThreadInfoPtr **info)
{
    virDomainIOThreadInfoPtr *info_ret = NULL;
    virBitmapPtr bitmap = NULL;
    virBitmapPtr cpumask = NULL;
    int hostcpus;
    size_t i;
    int ret = -1;

    if (targetDef->niothreadids == 0)
        return 0;

    if ((hostcpus = nodeGetCPUCount(NULL)) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(info_ret, targetDef->niothreadids) < 0)
        goto cleanup;

    for (i = 0; i < targetDef->niothreadids; i++) {
        if (VIR_ALLOC(info_ret[i]) < 0)
            goto cleanup;

        /* IOThread ID's are taken from the iothreadids list */
        info_ret[i]->iothread_id = targetDef->iothreadids[i]->iothread_id;

        cpumask = targetDef->iothreadids[i]->cpumask;
        if (!cpumask) {
            if (targetDef->cpumask) {
                cpumask = targetDef->cpumask;
            } else {
                if (!(bitmap = virBitmapNew(hostcpus)))
                    goto cleanup;
                virBitmapSetAll(bitmap);
                cpumask = bitmap;
            }
        }
        if (virBitmapToData(cpumask, &info_ret[i]->cpumap,
                            &info_ret[i]->cpumaplen) < 0)
            goto cleanup;
        virBitmapFree(bitmap);
        bitmap = NULL;
    }

    *info = info_ret;
    info_ret = NULL;
    ret = targetDef->niothreadids;

 cleanup:
    if (info_ret) {
        for (i = 0; i < targetDef->niothreadids; i++)
            virDomainIOThreadInfoFree(info_ret[i]);
        VIR_FREE(info_ret);
    }
    virBitmapFree(bitmap);

    return ret;
}

static int
qemuDomainGetIOThreadInfo(virDomainPtr dom,
                          virDomainIOThreadInfoPtr **info,
                          unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr targetDef = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetIOThreadInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, NULL, &targetDef) < 0)
        goto cleanup;

    if (!targetDef)
        ret = qemuDomainGetIOThreadsLive(driver, vm, info);
    else
        ret = qemuDomainGetIOThreadsConfig(targetDef, info);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainPinIOThread(virDomainPtr dom,
                      unsigned int iothread_id,
                      unsigned char *cpumap,
                      int maplen,
                      unsigned int flags)
{
    int ret = -1;
    virQEMUDriverPtr driver = dom->conn->privateData;
    virQEMUDriverConfigPtr cfg = NULL;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    virBitmapPtr pcpumap = NULL;
    qemuDomainObjPrivatePtr priv;
    virCgroupPtr cgroup_iothread = NULL;
    virObjectEventPtr event = NULL;
    char paramField[VIR_TYPED_PARAM_FIELD_LENGTH] = "";
    char *str = NULL;
    virTypedParameterPtr eventParams = NULL;
    int eventNparams = 0;
    int eventMaxparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;
    priv = vm->privateData;

    if (virDomainPinIOThreadEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Changing affinity for IOThread dynamically is "
                         "not allowed when CPU placement is 'auto'"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (!(pcpumap = virBitmapNewData(cpumap, maplen)))
        goto endjob;

    if (virBitmapIsAllClear(pcpumap)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Empty iothread cpumap list for pinning"));
        goto endjob;
    }

    if (def) {
        virDomainIOThreadIDDefPtr iothrid;
        virBitmapPtr cpumask;

        if (!(iothrid = virDomainIOThreadIDFind(def, iothread_id))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("iothread %d not found"), iothread_id);
            goto endjob;
        }

        if (!(cpumask = virBitmapNewData(cpumap, maplen)))
            goto endjob;

        virBitmapFree(iothrid->cpumask);
        iothrid->cpumask = cpumask;
        iothrid->autofill = false;

        /* Configure the corresponding cpuset cgroup before set affinity. */
        if (virCgroupHasController(priv->cgroup,
                                   VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_IOTHREAD,
                                   iothread_id, false, &cgroup_iothread) < 0)
                goto endjob;
            if (qemuSetupCgroupCpusetCpus(cgroup_iothread, pcpumap) < 0) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("failed to set cpuset.cpus in cgroup"
                                 " for iothread %d"), iothread_id);
                goto endjob;
            }
        } else {
            if (virProcessSetAffinity(iothrid->thread_id, pcpumap) < 0) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("failed to set cpu affinity for IOThread %d"),
                               iothread_id);
                goto endjob;
            }
        }

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;

        if (snprintf(paramField, VIR_TYPED_PARAM_FIELD_LENGTH,
                     VIR_DOMAIN_TUNABLE_CPU_IOTHREADSPIN, iothread_id) < 0) {
            goto endjob;
        }

        str = virBitmapFormat(pcpumap);
        if (virTypedParamsAddString(&eventParams, &eventNparams,
                                    &eventMaxparams, paramField, str) < 0)
            goto endjob;

        event = virDomainEventTunableNewFromDom(dom, eventParams, eventNparams);
    }

    if (persistentDef) {
        virDomainIOThreadIDDefPtr iothrid;
        virBitmapPtr cpumask;

        if (!(iothrid = virDomainIOThreadIDFind(persistentDef, iothread_id))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("iothreadid %d not found"), iothread_id);
            goto endjob;
        }

        if (!(cpumask = virBitmapNewData(cpumap, maplen)))
            goto endjob;

        virBitmapFree(iothrid->cpumask);
        iothrid->cpumask = cpumask;
        iothrid->autofill = false;

        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    if (cgroup_iothread)
        virCgroupFree(&cgroup_iothread);
    qemuDomainEventQueue(driver, event);
    VIR_FREE(str);
    virBitmapFree(pcpumap);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainHotplugAddIOThread(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             unsigned int iothread_id)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *alias = NULL;
    size_t idx;
    int rc = -1;
    int ret = -1;
    unsigned int orig_niothreads = vm->def->niothreadids;
    unsigned int exp_niothreads = vm->def->niothreadids;
    int new_niothreads = 0;
    qemuMonitorIOThreadInfoPtr *new_iothreads = NULL;
    virCgroupPtr cgroup_iothread = NULL;
    char *mem_mask = NULL;
    virDomainNumatuneMemMode mode;
    virDomainIOThreadIDDefPtr iothrid;
    virBitmapPtr cpumask;

    if (virDomainIOThreadIDFind(vm->def, iothread_id)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("an IOThread is already using iothread_id '%u'"),
                       iothread_id);
        goto cleanup;
    }

    if (virAsprintf(&alias, "iothread%u", iothread_id) < 0)
        return -1;

    qemuDomainObjEnterMonitor(driver, vm);

    rc = qemuMonitorAddObject(priv->mon, "iothread", alias, NULL);
    exp_niothreads++;
    if (rc < 0)
        goto exit_monitor;

    /* After hotplugging the IOThreads we need to re-detect the
     * IOThreads thread_id's, adjust the cgroups, thread affinity,
     * and add the thread_id to the vm->def->iothreadids list.
     */
    if ((new_niothreads = qemuMonitorGetIOThreads(priv->mon,
                                                  &new_iothreads)) < 0)
        goto exit_monitor;

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    if (new_niothreads != exp_niothreads) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("got wrong number of IOThread ids from QEMU monitor. "
                         "got %d, wanted %d"),
                       new_niothreads, exp_niothreads);
        vm->def->iothreads = new_niothreads;
        goto cleanup;
    }
    vm->def->iothreads = exp_niothreads;

    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mode) == 0 &&
        mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
        virDomainNumatuneMaybeFormatNodeset(vm->def->numa,
                                            priv->autoNodeset,
                                            &mem_mask, -1) < 0)
        goto cleanup;


    /*
     * If we've successfully added an IOThread, find out where we added it
     * in the QEMU IOThread list, so we can add it to our iothreadids list
     */
    for (idx = 0; idx < new_niothreads; idx++) {
        if (new_iothreads[idx]->iothread_id == iothread_id)
            break;
    }

    if (idx == new_niothreads) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find new IOThread '%u' in QEMU monitor."),
                       iothread_id);
        goto cleanup;
    }

    if (!(iothrid = virDomainIOThreadIDAdd(vm->def, iothread_id)))
        goto cleanup;

    iothrid->thread_id = new_iothreads[idx]->thread_id;

    /* Add IOThread to cgroup if present */
    if (priv->cgroup) {
        cgroup_iothread =
            qemuDomainAddCgroupForThread(priv->cgroup,
                                         VIR_CGROUP_THREAD_IOTHREAD,
                                         iothread_id, mem_mask,
                                         iothrid->thread_id);
        if (!cgroup_iothread)
            goto cleanup;
    }

    if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO)
        cpumask = priv->autoCpuset;
    else
        cpumask = vm->def->cpumask;

    if (cpumask) {
        if (qemuDomainHotplugPinThread(cpumask, iothread_id,
                                       iothrid->thread_id, cgroup_iothread) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    if (new_iothreads) {
        for (idx = 0; idx < new_niothreads; idx++)
            VIR_FREE(new_iothreads[idx]);
        VIR_FREE(new_iothreads);
    }
    VIR_FREE(mem_mask);
    virDomainAuditIOThread(vm, orig_niothreads, new_niothreads,
                           "update", rc == 0);
    virCgroupFree(&cgroup_iothread);
    VIR_FREE(alias);
    return ret;

 exit_monitor:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));
    goto cleanup;
}

static int
qemuDomainHotplugDelIOThread(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             unsigned int iothread_id)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t idx;
    char *alias = NULL;
    int rc = -1;
    int ret = -1;
    unsigned int orig_niothreads = vm->def->niothreadids;
    unsigned int exp_niothreads = vm->def->niothreadids;
    int new_niothreads = 0;
    qemuMonitorIOThreadInfoPtr *new_iothreads = NULL;

    /* Normally would use virDomainIOThreadIDFind, but we need the index
     * from whence to delete for later...
     */
    for (idx = 0; idx < vm->def->niothreadids; idx++) {
        if (iothread_id == vm->def->iothreadids[idx]->iothread_id)
            break;
    }

    if (idx == vm->def->niothreadids) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cannot find IOThread '%u' in iothreadids list"),
                       iothread_id);
        return -1;
    }

    if (virAsprintf(&alias, "iothread%u", iothread_id) < 0)
        return -1;

    qemuDomainObjEnterMonitor(driver, vm);

    rc = qemuMonitorDelObject(priv->mon, alias);
    exp_niothreads--;
    if (rc < 0)
        goto exit_monitor;

    if ((new_niothreads = qemuMonitorGetIOThreads(priv->mon,
                                                  &new_iothreads)) < 0)
        goto exit_monitor;

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    if (new_niothreads != exp_niothreads) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("got wrong number of IOThread ids from QEMU monitor. "
                         "got %d, wanted %d"),
                       new_niothreads, exp_niothreads);
        vm->def->iothreads = new_niothreads;
        goto cleanup;
    }
    vm->def->iothreads = exp_niothreads;

    virDomainIOThreadIDDel(vm->def, iothread_id);

    virDomainIOThreadSchedDelId(vm->def, iothread_id);

    if (qemuDomainDelCgroupForThread(priv->cgroup,
                                     VIR_CGROUP_THREAD_IOTHREAD,
                                     iothread_id) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (new_iothreads) {
        for (idx = 0; idx < new_niothreads; idx++)
            VIR_FREE(new_iothreads[idx]);
        VIR_FREE(new_iothreads);
    }
    virDomainAuditIOThread(vm, orig_niothreads, new_niothreads,
                           "update", rc == 0);
    VIR_FREE(alias);
    return ret;

 exit_monitor:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));
    goto cleanup;
}

static int
qemuDomainChgIOThread(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      unsigned int iothread_id,
                      bool add,
                      unsigned int flags)
{
    virQEMUDriverConfigPtr cfg = NULL;
    qemuDomainObjPrivatePtr priv;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1;

    if (iothread_id == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid value of 0 for iothread_id"));
        return -1;
    }

    cfg = virQEMUDriverGetConfig(driver);

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (def) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_OBJECT_IOTHREAD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("IOThreads not supported with this binary"));
            goto endjob;
        }

        if (add) {
            if (qemuDomainHotplugAddIOThread(driver, vm, iothread_id) < 0)
                goto endjob;
        } else {
            if (qemuDomainHotplugDelIOThread(driver, vm, iothread_id) < 0)
                goto endjob;
        }

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;
    }

    if (persistentDef) {
        if (add) {
            if (!virDomainIOThreadIDAdd(persistentDef, iothread_id))
                goto endjob;

            persistentDef->iothreads++;
        } else {
            virDomainIOThreadIDDefPtr iothrid;
            if (!(iothrid = virDomainIOThreadIDFind(persistentDef,
                                                    iothread_id))) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("cannot find IOThread '%u' in persistent "
                                 "iothreadids"),
                               iothread_id);
                goto endjob;
            }

            virDomainIOThreadIDDel(persistentDef, iothread_id);
            virDomainIOThreadSchedDelId(persistentDef, iothread_id);
            persistentDef->iothreads--;
        }

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainAddIOThread(virDomainPtr dom,
                      unsigned int iothread_id,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAddIOThreadEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = qemuDomainChgIOThread(driver, vm, iothread_id, true, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainDelIOThread(virDomainPtr dom,
                      unsigned int iothread_id,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    size_t i;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDelIOThreadEnsureACL(dom->conn, vm->def, flags) < 0)
           goto cleanup;

    /* If there is a disk using the IOThread to be removed, then fail. */
    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i]->iothread == iothread_id) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot remove IOThread %u since it "
                             "is being used by disk '%s'"),
                           iothread_id, vm->def->disks[i]->dst);
            goto cleanup;
        }
    }

    ret = qemuDomainChgIOThread(driver, vm, iothread_id, false, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int qemuDomainGetSecurityLabel(virDomainPtr dom, virSecurityLabelPtr seclabel)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    memset(seclabel, 0, sizeof(*seclabel));

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetSecurityLabelEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainVirtTypeToString(vm->def->virtType)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        if (virSecurityManagerGetProcessLabel(driver->securityManager,
                                              vm->def, vm->pid, seclabel) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to get security label"));
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int qemuDomainGetSecurityLabelList(virDomainPtr dom,
                                          virSecurityLabelPtr* seclabels)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    size_t i;
    int ret = -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetSecurityLabelListEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainVirtTypeToString(vm->def->virtType)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown virt type in domain definition '%d'"),
                       vm->def->virtType);
        goto cleanup;
    }

    /*
     * Check the comment in qemuDomainGetSecurityLabel function.
     */
    if (!virDomainObjIsActive(vm)) {
        /* No seclabels */
        *seclabels = NULL;
        ret = 0;
    } else {
        int len = 0;
        virSecurityManagerPtr* mgrs = virSecurityManagerGetNested(
                                            driver->securityManager);
        if (!mgrs)
            goto cleanup;

        /* Allocate seclabels array */
        for (i = 0; mgrs[i]; i++)
            len++;

        if (VIR_ALLOC_N((*seclabels), len) < 0) {
            VIR_FREE(mgrs);
            goto cleanup;
        }
        memset(*seclabels, 0, sizeof(**seclabels) * len);

        /* Fill the array */
        for (i = 0; i < len; i++) {
            if (virSecurityManagerGetProcessLabel(mgrs[i], vm->def, vm->pid,
                                                  &(*seclabels)[i]) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("Failed to get security label"));
                VIR_FREE(mgrs);
                VIR_FREE(*seclabels);
                goto cleanup;
            }
        }
        ret = len;
        VIR_FREE(mgrs);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int qemuNodeGetSecurityModel(virConnectPtr conn,
                                    virSecurityModelPtr secmodel)
{
    virQEMUDriverPtr driver = conn->privateData;
    char *p;
    int ret = 0;
    virCapsPtr caps = NULL;

    memset(secmodel, 0, sizeof(*secmodel));

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virNodeGetSecurityModelEnsureACL(conn) < 0)
        goto cleanup;

    /* We treat no driver as success, but simply return no data in *secmodel */
    if (caps->host.nsecModels == 0 ||
        caps->host.secModels[0].model == NULL)
        goto cleanup;

    p = caps->host.secModels[0].model;
    if (strlen(p) >= VIR_SECURITY_MODEL_BUFLEN-1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security model string exceeds max %d bytes"),
                       VIR_SECURITY_MODEL_BUFLEN-1);
        ret = -1;
        goto cleanup;
    }
    strcpy(secmodel->model, p);

    p = caps->host.secModels[0].doi;
    if (strlen(p) >= VIR_SECURITY_DOI_BUFLEN-1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security DOI string exceeds max %d bytes"),
                       VIR_SECURITY_DOI_BUFLEN-1);
        ret = -1;
        goto cleanup;
    }
    strcpy(secmodel->doi, p);

 cleanup:
    virObjectUnref(caps);
    return ret;
}


/**
 * qemuDomainSaveImageUpdateDef:
 * @driver: qemu driver data
 * @def: def of the domain from the save image
 * @newxml: user provided replacement XML
 *
 * Returns the new domain definition in case @newxml is ABI compatible with the
 * guest.
 */
static virDomainDefPtr
qemuDomainSaveImageUpdateDef(virQEMUDriverPtr driver,
                             virDomainDefPtr def,
                             const char *newxml)
{
    virDomainDefPtr ret = NULL;
    virDomainDefPtr newdef_migr = NULL;
    virDomainDefPtr newdef = NULL;
    virCapsPtr caps = NULL;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(newdef = virDomainDefParseString(newxml, caps, driver->xmlopt,
                                           VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    if (!(newdef_migr = qemuDomainDefCopy(driver,
                                          newdef,
                                          QEMU_DOMAIN_FORMAT_LIVE_FLAGS |
                                          VIR_DOMAIN_XML_MIGRATABLE)))
        goto cleanup;

    if (!virDomainDefCheckABIStability(def, newdef_migr)) {
        virResetLastError();

        /* Due to a bug in older version of external snapshot creation
         * code, the XML saved in the save image was not a migratable
         * XML. To ensure backwards compatibility with the change of the
         * saved XML type, we need to check the ABI compatibility against
         * the user provided XML if the check against the migratable XML
         * fails. Snapshots created prior to v1.1.3 have this issue. */
        if (!virDomainDefCheckABIStability(def, newdef))
            goto cleanup;

        /* use the user provided XML */
        ret = newdef;
        newdef = NULL;
    } else {
        ret = newdef_migr;
        newdef_migr = NULL;
    }

 cleanup:
    virObjectUnref(caps);
    virDomainDefFree(newdef);
    virDomainDefFree(newdef_migr);

    return ret;
}


/**
 * qemuDomainSaveImageOpen:
 * @driver: qemu driver data
 * @path: path of the save image
 * @ret_def: returns domain definition created from the XML stored in the image
 * @ret_header: returns structure filled with data from the image header
 * @xmlout: returns the XML from the image file (may be NULL)
 * @bypass_cache: bypass cache when opening the file
 * @wrapperFd: returns the file wrapper structure
 * @open_write: open the file for writing (for updates)
 * @unlink_corrupt: remove the image file if it is corrupted
 *
 * Returns the opened fd of the save image file and fills the appropriate fields
 * on success. On error returns -1 on most failures, -3 if corrupt image was
 * unlinked (no error raised).
 */
static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
qemuDomainSaveImageOpen(virQEMUDriverPtr driver,
                        const char *path,
                        virDomainDefPtr *ret_def,
                        virQEMUSaveHeaderPtr ret_header,
                        char **xmlout,
                        bool bypass_cache,
                        virFileWrapperFdPtr *wrapperFd,
                        bool open_write,
                        bool unlink_corrupt)
{
    int fd = -1;
    virQEMUSaveHeader header;
    char *xml = NULL;
    virDomainDefPtr def = NULL;
    int oflags = open_write ? O_RDWR : O_RDONLY;
    virCapsPtr caps = NULL;

    if (bypass_cache) {
        int directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("bypass cache unsupported by this system"));
            goto error;
        }
        oflags |= directFlag;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto error;

    if ((fd = qemuOpenFile(driver, NULL, path, oflags, NULL, NULL)) < 0)
        goto error;
    if (bypass_cache &&
        !(*wrapperFd = virFileWrapperFdNew(&fd, path,
                                           VIR_FILE_WRAPPER_BYPASS_CACHE)))
        goto error;

    if (saferead(fd, &header, sizeof(header)) != sizeof(header)) {
        if (unlink_corrupt) {
            if (VIR_CLOSE(fd) < 0 || unlink(path) < 0) {
                virReportSystemError(errno,
                                     _("cannot remove corrupt file: %s"),
                                     path);
                goto error;
            }
            return -3;
        }
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("failed to read qemu header"));
        goto error;
    }

    if (memcmp(header.magic, QEMU_SAVE_MAGIC, sizeof(header.magic)) != 0) {
        const char *msg = _("image magic is incorrect");

        if (memcmp(header.magic, QEMU_SAVE_PARTIAL,
                   sizeof(header.magic)) == 0) {
            msg = _("save image is incomplete");
            if (unlink_corrupt) {
                if (VIR_CLOSE(fd) < 0 || unlink(path) < 0) {
                    virReportSystemError(errno,
                                         _("cannot remove corrupt file: %s"),
                                         path);
                    goto error;
                }
                return -3;
            }
        }
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", msg);
        goto error;
    }

    if (header.version > QEMU_SAVE_VERSION) {
        /* convert endianess and try again */
        bswap_header(&header);
    }

    if (header.version > QEMU_SAVE_VERSION) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("image version is not supported (%d > %d)"),
                       header.version, QEMU_SAVE_VERSION);
        goto error;
    }

    if (header.xml_len <= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("invalid XML length: %d"), header.xml_len);
        goto error;
    }

    if (VIR_ALLOC_N(xml, header.xml_len) < 0)
        goto error;

    if (saferead(fd, xml, header.xml_len) != header.xml_len) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("failed to read XML"));
        goto error;
    }

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto error;

    if (xmlout)
        *xmlout = xml;
    else
        VIR_FREE(xml);

    *ret_def = def;
    *ret_header = header;

    virObjectUnref(caps);

    return fd;

 error:
    virDomainDefFree(def);
    VIR_FREE(xml);
    VIR_FORCE_CLOSE(fd);
    virObjectUnref(caps);

    return -1;
}

static int ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6)
qemuDomainSaveImageStartVM(virConnectPtr conn,
                           virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           int *fd,
                           const virQEMUSaveHeader *header,
                           const char *path,
                           bool start_paused,
                           qemuDomainAsyncJob asyncJob)
{
    int ret = -1;
    virObjectEventPtr event;
    int intermediatefd = -1;
    virCommandPtr cmd = NULL;
    char *errbuf = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if ((header->version == 2) &&
        (header->compressed != QEMU_SAVE_FORMAT_RAW)) {
        if (!(cmd = qemuCompressGetCommand(header->compressed)))
            goto cleanup;

        intermediatefd = *fd;
        *fd = -1;

        virCommandSetInputFD(cmd, intermediatefd);
        virCommandSetOutputFD(cmd, fd);
        virCommandSetErrorBuffer(cmd, &errbuf);
        virCommandDoAsyncIO(cmd);

        if (virCommandRunAsync(cmd, NULL) < 0) {
            *fd = intermediatefd;
            goto cleanup;
        }
    }

    /* Set the migration source and start it up. */
    ret = qemuProcessStart(conn, driver, vm, asyncJob,
                           "stdio", *fd, path, NULL,
                           VIR_NETDEV_VPORT_PROFILE_OP_RESTORE,
                           VIR_QEMU_PROCESS_START_PAUSED);

    if (intermediatefd != -1) {
        if (ret < 0) {
            /* if there was an error setting up qemu, the intermediate
             * process will wait forever to write to stdout, so we
             * must manually kill it.
             */
            VIR_FORCE_CLOSE(intermediatefd);
            VIR_FORCE_CLOSE(*fd);
        }

        if (virCommandWait(cmd, NULL) < 0) {
            qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED, 0);
            ret = -1;
        }
        VIR_DEBUG("Decompression binary stderr: %s", NULLSTR(errbuf));
    }
    VIR_FORCE_CLOSE(intermediatefd);

    if (VIR_CLOSE(*fd) < 0) {
        virReportSystemError(errno, _("cannot close file: %s"), path);
        ret = -1;
    }

    if (ret < 0) {
        virDomainAuditStart(vm, "restored", false);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    virDomainAuditStart(vm, "restored", true);
    qemuDomainEventQueue(driver, event);


    /* If it was running before, resume it now unless caller requested pause. */
    if (header->was_running && !start_paused) {
        if (qemuProcessStartCPUs(driver, vm, conn,
                                 VIR_DOMAIN_RUNNING_RESTORED,
                                 asyncJob) < 0) {
            if (virGetLastError() == NULL)
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("failed to resume domain"));
            goto cleanup;
        }
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto cleanup;
        }
    } else {
        int detail = (start_paused ? VIR_DOMAIN_EVENT_SUSPENDED_PAUSED :
                      VIR_DOMAIN_EVENT_SUSPENDED_RESTORED);
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         detail);
        qemuDomainEventQueue(driver, event);
    }

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(errbuf);
    if (virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                 vm->def, path) < 0)
        VIR_WARN("failed to restore save state label on %s", path);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainRestoreFlags(virConnectPtr conn,
                       const char *path,
                       const char *dxml,
                       unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuDomainObjPrivatePtr priv = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    char *xml = NULL;
    char *xmlout = NULL;
    const char *newxml = dxml;
    int fd = -1;
    int ret = -1;
    virQEMUSaveHeader header;
    virFileWrapperFdPtr wrapperFd = NULL;
    bool hook_taint = false;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE |
                  VIR_DOMAIN_SAVE_RUNNING |
                  VIR_DOMAIN_SAVE_PAUSED, -1);


    virNWFilterReadLockFilterUpdates();

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, &xml,
                                 (flags & VIR_DOMAIN_SAVE_BYPASS_CACHE) != 0,
                                 &wrapperFd, false, false);
    if (fd < 0)
        goto cleanup;

    if (virDomainRestoreFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        int hookret;

        if ((hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, def->name,
                                   VIR_HOOK_QEMU_OP_RESTORE,
                                   VIR_HOOK_SUBOP_BEGIN,
                                   NULL,
                                   dxml ? dxml : xml,
                                   &xmlout)) < 0)
            goto cleanup;

        if (hookret == 0 && !virStringIsEmpty(xmlout)) {
            VIR_DEBUG("Using hook-filtered domain XML: %s", xmlout);
            hook_taint = true;
            newxml = xmlout;
        }
    }

    if (newxml) {
        virDomainDefPtr tmp;
        if (!(tmp = qemuDomainSaveImageUpdateDef(driver, def, newxml)))
            goto cleanup;

        virDomainDefFree(def);
        def = tmp;
    }

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    virObjectRef(vm);
    def = NULL;

    if (flags & VIR_DOMAIN_SAVE_RUNNING)
        header.was_running = 1;
    else if (flags & VIR_DOMAIN_SAVE_PAUSED)
        header.was_running = 0;

    if (hook_taint) {
        priv = vm->privateData;
        priv->hookRun = true;
    }

    if (qemuProcessBeginJob(driver, vm) < 0)
        goto cleanup;

    ret = qemuDomainSaveImageStartVM(conn, driver, vm, &fd, &header, path,
                                     false, QEMU_ASYNC_JOB_START);
    if (virFileWrapperFdClose(wrapperFd) < 0)
        VIR_WARN("Failed to close %s", path);

    qemuProcessEndJob(driver, vm);

 cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(xml);
    VIR_FREE(xmlout);
    virFileWrapperFdFree(wrapperFd);
    if (vm && ret < 0)
        qemuDomainRemoveInactive(driver, vm);
    virDomainObjEndAPI(&vm);
    virNWFilterUnlockFilterUpdates();
    return ret;
}

static int
qemuDomainRestore(virConnectPtr conn,
                  const char *path)
{
    return qemuDomainRestoreFlags(conn, path, NULL, 0);
}

static char *
qemuDomainSaveImageGetXMLDesc(virConnectPtr conn, const char *path,
                              unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    char *ret = NULL;
    virDomainDefPtr def = NULL;
    int fd = -1;
    virQEMUSaveHeader header;

    /* We only take subset of virDomainDefFormat flags.  */
    virCheckFlags(VIR_DOMAIN_XML_SECURE, NULL);

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, NULL,
                                 false, NULL, false, false);

    if (fd < 0)
        goto cleanup;

    if (virDomainSaveImageGetXMLDescEnsureACL(conn, def, flags) < 0)
        goto cleanup;

    ret = qemuDomainDefFormatXML(driver, def, flags);

 cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    return ret;
}

static int
qemuDomainSaveImageDefineXML(virConnectPtr conn, const char *path,
                             const char *dxml, unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;
    virDomainDefPtr def = NULL;
    virDomainDefPtr newdef = NULL;
    int fd = -1;
    virQEMUSaveHeader header;
    char *xml = NULL;
    size_t len;
    int state = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_RUNNING |
                  VIR_DOMAIN_SAVE_PAUSED, -1);

    if (flags & VIR_DOMAIN_SAVE_RUNNING)
        state = 1;
    else if (flags & VIR_DOMAIN_SAVE_PAUSED)
        state = 0;

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, &xml,
                                 false, NULL, true, false);

    if (fd < 0)
        goto cleanup;

    if (virDomainSaveImageDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (STREQ(xml, dxml) &&
        (state < 0 || state == header.was_running)) {
        /* no change to the XML */
        ret = 0;
        goto cleanup;
    }

    if (state >= 0)
        header.was_running = state;

    if (!(newdef = qemuDomainSaveImageUpdateDef(driver, def, dxml)))
        goto cleanup;

    VIR_FREE(xml);

    xml = qemuDomainDefFormatXML(driver, newdef,
                                 VIR_DOMAIN_XML_INACTIVE |
                                 VIR_DOMAIN_XML_SECURE |
                                 VIR_DOMAIN_XML_MIGRATABLE);
    if (!xml)
        goto cleanup;
    len = strlen(xml) + 1;

    if (len > header.xml_len) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("new xml too large to fit in file"));
        goto cleanup;
    }
    if (VIR_EXPAND_N(xml, len, header.xml_len - len) < 0)
        goto cleanup;

    if (lseek(fd, 0, SEEK_SET) != 0) {
        virReportSystemError(errno, _("cannot seek in '%s'"), path);
        goto cleanup;
    }
    if (safewrite(fd, &header, sizeof(header)) != sizeof(header) ||
        safewrite(fd, xml, len) != len ||
        VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("failed to write xml to '%s'"), path);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainDefFree(def);
    virDomainDefFree(newdef);
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(xml);
    return ret;
}

/* Return 0 on success, 1 if incomplete saved image was silently unlinked,
 * and -1 on failure with error raised.  */
static int
qemuDomainObjRestore(virConnectPtr conn,
                     virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     const char *path,
                     bool start_paused,
                     bool bypass_cache,
                     qemuDomainAsyncJob asyncJob)
{
    virDomainDefPtr def = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int fd = -1;
    int ret = -1;
    char *xml = NULL;
    char *xmlout = NULL;
    virQEMUSaveHeader header;
    virFileWrapperFdPtr wrapperFd = NULL;

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, &xml,
                                 bypass_cache, &wrapperFd, false, true);
    if (fd < 0) {
        if (fd == -3)
            ret = 1;
        goto cleanup;
    }

    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        int hookret;

        if ((hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, def->name,
                                   VIR_HOOK_QEMU_OP_RESTORE,
                                   VIR_HOOK_SUBOP_BEGIN,
                                   NULL, xml, &xmlout)) < 0)
            goto cleanup;

        if (hookret == 0 && !virStringIsEmpty(xmlout)) {
            virDomainDefPtr tmp;

            VIR_DEBUG("Using hook-filtered domain XML: %s", xmlout);

            if (!(tmp = qemuDomainSaveImageUpdateDef(driver, def, xmlout)))
                goto cleanup;

            virDomainDefFree(def);
            def = tmp;
            priv->hookRun = true;
        }
    }

    if (STRNEQ(vm->def->name, def->name) ||
        memcmp(vm->def->uuid, def->uuid, VIR_UUID_BUFLEN)) {
        char vm_uuidstr[VIR_UUID_STRING_BUFLEN];
        char def_uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(vm->def->uuid, vm_uuidstr);
        virUUIDFormat(def->uuid, def_uuidstr);
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot restore domain '%s' uuid %s from a file"
                         " which belongs to domain '%s' uuid %s"),
                       vm->def->name, vm_uuidstr,
                       def->name, def_uuidstr);
        goto cleanup;
    }

    virDomainObjAssignDef(vm, def, true, NULL);
    def = NULL;

    ret = qemuDomainSaveImageStartVM(conn, driver, vm, &fd, &header, path,
                                     start_paused, asyncJob);
    if (virFileWrapperFdClose(wrapperFd) < 0)
        VIR_WARN("Failed to close %s", path);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(xmlout);
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    virFileWrapperFdFree(wrapperFd);
    return ret;
}


static char
*qemuDomainGetXMLDesc(virDomainPtr dom,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainUpdateCurrentMemorySize(driver, vm) < 0)
        goto cleanup;

    if ((flags & VIR_DOMAIN_XML_MIGRATABLE))
        flags |= QEMU_DOMAIN_FORMAT_LIVE_FLAGS;

    ret = qemuDomainFormatXML(driver, vm, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static char *qemuConnectDomainXMLFromNative(virConnectPtr conn,
                                            const char *format,
                                            const char *config,
                                            unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    char *xml = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STRNEQ(format, QEMU_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), format);
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    def = qemuParseCommandLineString(caps, driver->xmlopt, config,
                                     NULL, NULL, NULL);
    if (!def)
        goto cleanup;

    if (!def->name && VIR_STRDUP(def->name, "unnamed") < 0)
        goto cleanup;

    xml = qemuDomainDefFormatXML(driver, def, VIR_DOMAIN_XML_INACTIVE);

 cleanup:
    virDomainDefFree(def);
    virObjectUnref(caps);
    return xml;
}

static char *qemuConnectDomainXMLToNative(virConnectPtr conn,
                                          const char *format,
                                          const char *xmlData,
                                          unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainChrSourceDef monConfig;
    virQEMUCapsPtr qemuCaps = NULL;
    bool monitor_json = false;
    virCommandPtr cmd = NULL;
    char *ret = NULL;
    size_t i;
    virQEMUDriverConfigPtr cfg;
    virCapsPtr caps = NULL;

    virCheckFlags(0, NULL);

    cfg = virQEMUDriverGetConfig(driver);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STRNEQ(format, QEMU_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), format);
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    def = virDomainDefParseString(xmlData, caps, driver->xmlopt,
                                  VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                  VIR_DOMAIN_DEF_PARSE_ABI_UPDATE);
    if (!def)
        goto cleanup;

    if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, def->emulator)))
        goto cleanup;

    /* Since we're just exporting args, we can't do bridge/network/direct
     * setups, since libvirt will normally create TAP/macvtap devices
     * directly. We convert those configs into generic 'ethernet'
     * config and assume the user has suitable 'ifup-qemu' scripts
     */
    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        int bootIndex = net->info.bootIndex;
        char *model = net->model;
        virMacAddr mac = net->mac;

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            int actualType = virDomainNetGetActualType(net);
            const char *brname;

            VIR_FREE(net->data.network.name);
            VIR_FREE(net->data.network.portgroup);
            if ((actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) &&
                (brname = virDomainNetGetActualBridgeName(net))) {

                char *brnamecopy;
                size_t j;

                if (VIR_STRDUP(brnamecopy, brname) < 0)
                    goto cleanup;

                virDomainActualNetDefFree(net->data.network.actual);

                memset(net, 0, sizeof(*net));

                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                net->script = NULL;
                net->data.ethernet.dev = brnamecopy;
                for (j = 0; j < net->nips; j++)
                    VIR_FREE(net->ips[j]);
                VIR_FREE(net->ips);
                net->nips = 0;

            } else {
                /* actualType is either NETWORK or DIRECT. In either
                 * case, the best we can do is NULL everything out.
                 */
                size_t j;
                virDomainActualNetDefFree(net->data.network.actual);
                memset(net, 0, sizeof(*net));

                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                net->script = NULL;
                net->data.ethernet.dev = NULL;
                for (j = 0; j < net->nips; j++)
                    VIR_FREE(net->ips[j]);
                VIR_FREE(net->ips);
                net->nips = 0;
            }
        } else if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            size_t j;
            VIR_FREE(net->data.direct.linkdev);

            memset(net, 0, sizeof(*net));

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            net->script = NULL;
            net->data.ethernet.dev = NULL;
            for (j = 0; j < net->nips; j++)
                VIR_FREE(net->ips[j]);
            VIR_FREE(net->ips);
            net->nips = 0;
        } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            char *script = net->script;
            char *brname = net->data.bridge.brname;
            size_t nips = net->nips;
            virDomainNetIpDefPtr *ips = net->ips;

            memset(net, 0, sizeof(*net));

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            net->script = script;
            net->data.ethernet.dev = brname;
            net->nips = nips;
            net->ips = ips;
        }

        VIR_FREE(net->virtPortProfile);
        net->info.bootIndex = bootIndex;
        net->model = model;
        net->mac = mac;
    }

    monitor_json = virQEMUCapsGet(qemuCaps, QEMU_CAPS_MONITOR_JSON);

    if (qemuProcessPrepareMonitorChr(cfg, &monConfig, def->name) < 0)
        goto cleanup;

    if (qemuAssignDeviceAliases(def, qemuCaps) < 0)
        goto cleanup;

    if (qemuDomainAssignAddresses(def, qemuCaps, NULL) < 0)
        goto cleanup;

    /* do fake auto-alloc of graphics ports, if such config is used */
    for (i = 0; i < def->ngraphics; ++i) {
        virDomainGraphicsDefPtr graphics = def->graphics[i];
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            !graphics->data.vnc.socket && graphics->data.vnc.autoport) {
            graphics->data.vnc.port = 5900;
        } else if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            if (qemuProcessSPICEAllocatePorts(driver, cfg, graphics, false) < 0)
                goto cleanup;
        }
    }

    if (!(cmd = qemuBuildCommandLine(conn, driver, def,
                                     &monConfig, monitor_json, qemuCaps,
                                     NULL, NULL,
                                     VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,
                                     &buildCommandLineCallbacks,
                                     true,
                                     qemuCheckFips(),
                                     NULL, NULL, NULL)))
        goto cleanup;

    ret = virCommandToString(cmd);

 cleanup:
    virObjectUnref(qemuCaps);
    virCommandFree(cmd);
    virDomainDefFree(def);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


static int qemuConnectListDefinedDomains(virConnectPtr conn,
                                         char **const names, int nnames) {
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        goto cleanup;

    ret = virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                           virConnectListDefinedDomainsCheckACL,
                                           conn);

 cleanup:
    return ret;
}

static int qemuConnectNumOfDefinedDomains(virConnectPtr conn)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        goto cleanup;

    ret = virDomainObjListNumOfDomains(driver->domains, false,
                                       virConnectNumOfDefinedDomainsCheckACL,
                                       conn);

 cleanup:
    return ret;
}


static int
qemuDomainObjStart(virConnectPtr conn,
                   virQEMUDriverPtr driver,
                   virDomainObjPtr vm,
                   unsigned int flags,
                   qemuDomainAsyncJob asyncJob)
{
    int ret = -1;
    char *managed_save;
    bool start_paused = (flags & VIR_DOMAIN_START_PAUSED) != 0;
    bool autodestroy = (flags & VIR_DOMAIN_START_AUTODESTROY) != 0;
    bool bypass_cache = (flags & VIR_DOMAIN_START_BYPASS_CACHE) != 0;
    bool force_boot = (flags & VIR_DOMAIN_START_FORCE_BOOT) != 0;
    unsigned int start_flags = VIR_QEMU_PROCESS_START_COLD;

    start_flags |= start_paused ? VIR_QEMU_PROCESS_START_PAUSED : 0;
    start_flags |= autodestroy ? VIR_QEMU_PROCESS_START_AUTODESTROY : 0;

    /*
     * If there is a managed saved state restore it instead of starting
     * from scratch. The old state is removed once the restoring succeeded.
     */
    managed_save = qemuDomainManagedSavePath(driver, vm);

    if (!managed_save)
        goto cleanup;

    if (virFileExists(managed_save)) {
        if (force_boot) {
            if (unlink(managed_save) < 0) {
                virReportSystemError(errno,
                                     _("cannot remove managed save file %s"),
                                     managed_save);
                goto cleanup;
            }
            vm->hasManagedSave = false;
        } else {
            ret = qemuDomainObjRestore(conn, driver, vm, managed_save,
                                       start_paused, bypass_cache, asyncJob);

            if (ret == 0) {
                if (unlink(managed_save) < 0)
                    VIR_WARN("Failed to remove the managed state %s", managed_save);
                else
                    vm->hasManagedSave = false;

                goto cleanup;
            } else if (ret < 0) {
                VIR_WARN("Unable to restore from managed state %s. "
                         "Maybe the file is corrupted?", managed_save);
                goto cleanup;
            } else {
                VIR_WARN("Ignoring incomplete managed state %s", managed_save);
            }
        }
    }

    ret = qemuProcessStart(conn, driver, vm, asyncJob,
                           NULL, -1, NULL, NULL,
                           VIR_NETDEV_VPORT_PROFILE_OP_CREATE, start_flags);
    virDomainAuditStart(vm, "booted", ret >= 0);
    if (ret >= 0) {
        virObjectEventPtr event =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
        if (event) {
            qemuDomainEventQueue(driver, event);
            if (start_paused) {
                event = virDomainEventLifecycleNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_SUSPENDED,
                                                 VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
                qemuDomainEventQueue(driver, event);
            }
        }
    }

 cleanup:
    VIR_FREE(managed_save);
    return ret;
}

static int
qemuDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_BYPASS_CACHE |
                  VIR_DOMAIN_START_FORCE_BOOT, -1);

    virNWFilterReadLockFilterUpdates();

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuProcessBeginJob(driver, vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is already running"));
        goto endjob;
    }

    if (qemuDomainObjStart(dom->conn, driver, vm, flags,
                           QEMU_ASYNC_JOB_START) < 0)
        goto endjob;

    ret = 0;

 endjob:
    qemuProcessEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virNWFilterUnlockFilterUpdates();
    return ret;
}

static int
qemuDomainCreate(virDomainPtr dom)
{
    return qemuDomainCreateWithFlags(dom, 0);
}

static virDomainPtr qemuDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainDefPtr oldDef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virObjectEventPtr event = NULL;
    virQEMUCapsPtr qemuCaps = NULL;
    virQEMUDriverConfigPtr cfg;
    virCapsPtr caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE;

    cfg = virQEMUDriverGetConfig(driver);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        parse_flags)))
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, def->emulator)))
        goto cleanup;

    if (qemuCanonicalizeMachine(def, qemuCaps) < 0)
        goto cleanup;

    if (qemuDomainAssignAddresses(def, qemuCaps, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   0, &oldDef)))
        goto cleanup;

    virObjectRef(vm);
    def = NULL;
    if (qemuDomainHasBlockjob(vm, true)) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE, "%s",
                       _("domain has active block job"));
        virDomainObjAssignDef(vm, NULL, false, NULL);
        goto cleanup;
    }
    vm->persistent = 1;

    if (virDomainSaveConfig(cfg->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        if (oldDef) {
            /* There is backup so this VM was defined before.
             * Just restore the backup. */
            VIR_INFO("Restoring domain '%s' definition", vm->def->name);
            if (virDomainObjIsActive(vm))
                vm->newDef = oldDef;
            else
                vm->def = oldDef;
            oldDef = NULL;
        } else {
            /* Brand new domain. Remove it */
            VIR_INFO("Deleting domain '%s'", vm->def->name);
            vm->persistent = 0;
            qemuDomainRemoveInactive(driver, vm);
        }
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !oldDef ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    VIR_INFO("Creating domain '%s'", vm->def->name);
    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

 cleanup:
    virDomainDefFree(oldDef);
    virDomainDefFree(def);
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    virObjectUnref(qemuCaps);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return dom;
}

static virDomainPtr
qemuDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return qemuDomainDefineXMLFlags(conn, xml, 0);
}

static int
qemuDomainUndefineFlags(virDomainPtr dom,
                        unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    char *name = NULL;
    int ret = -1;
    int nsnapshots;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE |
                  VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA |
                  VIR_DOMAIN_UNDEFINE_NVRAM, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainUndefineFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm) &&
        (nsnapshots = virDomainSnapshotObjListNum(vm->snapshots, NULL, 0))) {
        if (!(flags & VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("cannot delete inactive domain with %d "
                             "snapshots"),
                           nsnapshots);
            goto cleanup;
        }
        if (qemuDomainSnapshotDiscardAllMetadata(driver, vm) < 0)
            goto cleanup;
    }

    name = qemuDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    if (virFileExists(name)) {
        if (flags & VIR_DOMAIN_UNDEFINE_MANAGED_SAVE) {
            if (unlink(name) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Failed to remove domain managed "
                                 "save image"));
                goto cleanup;
            }
        } else {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Refusing to undefine while domain managed "
                             "save image exists"));
            goto cleanup;
        }
    }

    if (!virDomainObjIsActive(vm) &&
        vm->def->os.loader && vm->def->os.loader->nvram &&
        virFileExists(vm->def->os.loader->nvram)) {
        if (!(flags & VIR_DOMAIN_UNDEFINE_NVRAM)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot delete inactive domain with nvram"));
            goto cleanup;
        }

        if (unlink(vm->def->os.loader->nvram) < 0) {
            virReportSystemError(errno,
                                 _("failed to remove nvram: %s"),
                                 vm->def->os.loader->nvram);
            goto cleanup;
        }
    }

    if (virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm) < 0)
        goto cleanup;

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    VIR_INFO("Undefining domain '%s'", vm->def->name);

    /* If the domain is active, keep it running but set it as transient.
     * domainDestroy and domainShutdown will take care of removing the
     * domain obj from the hash table.
     */
    vm->persistent = 0;
    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactive(driver, vm);

    ret = 0;

 cleanup:
    VIR_FREE(name);
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainUndefine(virDomainPtr dom)
{
    return qemuDomainUndefineFlags(dom, 0);
}

static int
qemuDomainAttachDeviceLive(virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev,
                           virDomainPtr dom)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    int ret = -1;
    const char *alias = NULL;

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        qemuDomainObjCheckDiskTaint(driver, vm, dev->data.disk, NULL);
        ret = qemuDomainAttachDeviceDiskLive(dom->conn, driver, vm, dev);
        if (!ret) {
            alias = dev->data.disk->info.alias;
            dev->data.disk = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        ret = qemuDomainAttachControllerDevice(driver, vm, dev->data.controller);
        if (!ret) {
            alias = dev->data.controller->info.alias;
            dev->data.controller = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
        ret = qemuDomainAttachLease(driver, vm,
                                    dev->data.lease);
        if (ret == 0)
            dev->data.lease = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        qemuDomainObjCheckNetTaint(driver, vm, dev->data.net, NULL);
        ret = qemuDomainAttachNetDevice(dom->conn, driver, vm,
                                        dev->data.net);
        if (!ret) {
            alias = dev->data.net->info.alias;
            dev->data.net = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        qemuDomainObjCheckHostdevTaint(driver, vm, dev->data.hostdev, NULL);
        ret = qemuDomainAttachHostDevice(dom->conn, driver, vm,
                                         dev->data.hostdev);
        if (!ret) {
            alias = dev->data.hostdev->info->alias;
            dev->data.hostdev = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_REDIRDEV:
        ret = qemuDomainAttachRedirdevDevice(driver, vm,
                                             dev->data.redirdev);
        if (!ret) {
            alias = dev->data.redirdev->info.alias;
            dev->data.redirdev = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainAttachChrDevice(driver, vm,
                                        dev->data.chr);
        if (!ret) {
            alias = dev->data.chr->info.alias;
            dev->data.chr = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_RNG:
        ret = qemuDomainAttachRNGDevice(driver, vm,
                                        dev->data.rng);
        if (!ret) {
            alias = dev->data.rng->info.alias;
            dev->data.rng = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_MEMORY:
        /* note that qemuDomainAttachMemory always consumes dev->data.memory
         * and dispatches DeviceAdded event on success */
        ret = qemuDomainAttachMemory(driver, vm,
                                     dev->data.memory);
        dev->data.memory = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live attach of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    if (alias) {
        /* queue the event before the alias has a chance to get freed
         * if the domain disappears while qemuDomainUpdateDeviceList
         * is in monitor */
        virObjectEventPtr event;
        event = virDomainEventDeviceAddedNewFromObj(vm, alias);
        qemuDomainEventQueue(driver, event);
    }

    if (ret == 0)
        ret = qemuDomainUpdateDeviceList(driver, vm, QEMU_ASYNC_JOB_NONE);

    return ret;
}

static int
qemuDomainDetachDeviceControllerLive(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virDomainControllerDefPtr cont = dev->data.controller;
    int ret = -1;

    switch (cont->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        ret = qemuDomainDetachControllerDevice(driver, vm, dev);
        break;
    default :
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("'%s' controller cannot be hot unplugged."),
                       virDomainControllerTypeToString(cont->type));
    }
    return ret;
}

static int
qemuDomainDetachDeviceLive(virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev,
                           virDomainPtr dom)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    int ret = -1;

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        ret = qemuDomainDetachDeviceDiskLive(driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        ret = qemuDomainDetachDeviceControllerLive(driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
        ret = qemuDomainDetachLease(driver, vm, dev->data.lease);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        ret = qemuDomainDetachNetDevice(driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = qemuDomainDetachHostDevice(driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainDetachChrDevice(driver, vm, dev->data.chr);
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        ret = qemuDomainDetachRNGDevice(driver, vm, dev->data.rng);
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        ret = qemuDomainDetachMemoryDevice(driver, vm, dev->data.memory);
        break;

    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live detach of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    if (ret == 0)
        ret = qemuDomainUpdateDeviceList(driver, vm, QEMU_ASYNC_JOB_NONE);

    return ret;
}

static int
qemuDomainChangeDiskLive(virConnectPtr conn,
                         virDomainObjPtr vm,
                         virDomainDeviceDefPtr dev,
                         virQEMUDriverPtr driver,
                         bool force)
{
    virDomainDiskDefPtr disk = dev->data.disk;
    virDomainDiskDefPtr orig_disk = NULL;
    int startupPolicy;
    int ret = -1;

    if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
        goto cleanup;

    if (qemuDomainDetermineDiskChain(driver, vm, disk, false, true) < 0)
        goto cleanup;

    if (!(orig_disk = virDomainDiskFindByBusAndDst(vm->def,
                                                   disk->bus, disk->dst))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No device with bus '%s' and target '%s'"),
                       virDomainDiskBusTypeToString(disk->bus),
                       disk->dst);
        goto cleanup;
    }

    startupPolicy = orig_disk->startupPolicy;

    switch ((virDomainDiskDevice) disk->device) {
    case VIR_DOMAIN_DISK_DEVICE_CDROM:
    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        if (!qemuDomainDiskChangeSupported(disk, orig_disk))
            goto cleanup;

        orig_disk->startupPolicy = dev->data.disk->startupPolicy;

        if (qemuDomainDiskSourceDiffers(conn, disk, orig_disk)) {
            /* Add the new disk src into shared disk hash table */
            if (qemuAddSharedDevice(driver, dev, vm->def->name) < 0)
                goto cleanup;

            if (qemuDomainChangeEjectableMedia(driver, conn, vm,
                                               orig_disk, dev->data.disk->src, force) < 0) {
                ignore_value(qemuRemoveSharedDisk(driver, dev->data.disk, vm->def->name));
                goto rollback;
            }

            dev->data.disk->src = NULL;
        }
        break;

    case VIR_DOMAIN_DISK_DEVICE_DISK:
    case VIR_DOMAIN_DISK_DEVICE_LUN:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk bus '%s' cannot be updated."),
                       virDomainDiskBusTypeToString(disk->bus));
        goto cleanup;
        break;

    case VIR_DOMAIN_DISK_DEVICE_LAST:
        /* nada */
        break;
    }

    ret = 0;
 cleanup:
    return ret;

 rollback:
    orig_disk->startupPolicy = startupPolicy;
    goto cleanup;
}

static int
qemuDomainUpdateDeviceLive(virConnectPtr conn,
                           virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev,
                           virDomainPtr dom,
                           bool force)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    int ret = -1;

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        qemuDomainObjCheckDiskTaint(driver, vm, dev->data.disk, NULL);
        ret = qemuDomainChangeDiskLive(conn, vm, dev, driver, force);
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        ret = qemuDomainChangeGraphics(driver, vm, dev->data.graphics);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        ret = qemuDomainChangeNet(driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("live update of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
qemuDomainAttachDeviceConfig(virQEMUCapsPtr qemuCaps,
                             virDomainDefPtr vmdef,
                             virDomainDeviceDefPtr dev,
                             virConnectPtr conn)
{
    virDomainDiskDefPtr disk;
    virDomainNetDefPtr net;
    virDomainHostdevDefPtr hostdev;
    virDomainLeaseDefPtr lease;
    virDomainControllerDefPtr controller;
    virDomainFSDefPtr fs;

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (virDomainDiskIndexByName(vmdef, disk->dst, true) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("target %s already exists"), disk->dst);
            return -1;
        }
        if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
            return -1;
        if (qemuCheckDiskConfig(disk) < 0)
            return -1;
        if (virDomainDiskInsert(vmdef, disk))
            return -1;
        /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
        dev->data.disk = NULL;
        if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            if (virDomainDefAddImplicitControllers(vmdef) < 0)
                return -1;
        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if (virDomainNetInsert(vmdef, net))
            return -1;
        dev->data.net = NULL;
        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        hostdev = dev->data.hostdev;
        if (virDomainHostdevFind(vmdef, hostdev, NULL) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("device is already in the domain configuration"));
            return -1;
        }
        if (virDomainHostdevInsert(vmdef, hostdev))
            return -1;
        dev->data.hostdev = NULL;
        if (virDomainDefAddImplicitControllers(vmdef) < 0)
            return -1;
        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
        lease = dev->data.lease;
        if (virDomainLeaseIndex(vmdef, lease) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Lease %s in lockspace %s already exists"),
                           lease->key, NULLSTR(lease->lockspace));
            return -1;
        }
        if (virDomainLeaseInsert(vmdef, lease) < 0)
            return -1;

        /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
        dev->data.lease = NULL;
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        controller = dev->data.controller;
        if (virDomainControllerFind(vmdef, controller->type,
                                    controller->idx) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Target already exists"));
            return -1;
        }

        if (virDomainControllerInsert(vmdef, controller) < 0)
            return -1;
        dev->data.controller = NULL;

        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        if (qemuDomainChrInsert(vmdef, dev->data.chr) < 0)
            return -1;
        dev->data.chr = NULL;
        if (virDomainDefAddImplicitControllers(vmdef) < 0)
            return -1;
        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_FS:
        fs = dev->data.fs;
        if (virDomainFSIndexByName(vmdef, fs->dst) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                         "%s", _("Target already exists"));
            return -1;
        }

        if (virDomainFSInsert(vmdef, fs) < 0)
            return -1;
        dev->data.fs = NULL;
        break;

    case VIR_DOMAIN_DEVICE_RNG:
        if (dev->data.rng->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            virDomainDefHasDeviceAddress(vmdef, &dev->data.rng->info)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("a device with the same address already exists "));
            return -1;
        }

        if (virDomainRNGInsert(vmdef, dev->data.rng, false) < 0)
            return -1;
        dev->data.rng = NULL;

        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_MEMORY:
        if (vmdef->nmems == vmdef->mem.memory_slots) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("no free memory device slot available"));
            return -1;
        }

        if (vmdef->mem.cur_balloon == virDomainDefGetMemoryActual(vmdef))
            vmdef->mem.cur_balloon += dev->data.memory->size;

        if (virDomainMemoryInsert(vmdef, dev->data.memory) < 0)
            return -1;
        dev->data.memory = NULL;
        break;

    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
         virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                        _("persistent attach of device '%s' is not supported"),
                        virDomainDeviceTypeToString(dev->type));
         return -1;
    }
    return 0;
}


static int
qemuDomainDetachDeviceConfig(virDomainDefPtr vmdef,
                             virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk, det_disk;
    virDomainNetDefPtr net;
    virDomainHostdevDefPtr hostdev, det_hostdev;
    virDomainLeaseDefPtr lease, det_lease;
    virDomainControllerDefPtr cont, det_cont;
    virDomainChrDefPtr chr;
    virDomainFSDefPtr fs;
    int idx;

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (!(det_disk = virDomainDiskRemoveByName(vmdef, disk->dst))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("no target device %s"), disk->dst);
            return -1;
        }
        virDomainDiskDefFree(det_disk);
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if ((idx = virDomainNetFindIdx(vmdef, net)) < 0)
            return -1;

        /* this is guaranteed to succeed */
        virDomainNetDefFree(virDomainNetRemove(vmdef, idx));
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV: {
        hostdev = dev->data.hostdev;
        if ((idx = virDomainHostdevFind(vmdef, hostdev, &det_hostdev)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("device not present in domain configuration"));
            return -1;
        }
        virDomainHostdevRemove(vmdef, idx);
        virDomainHostdevDefFree(det_hostdev);
        break;
    }

    case VIR_DOMAIN_DEVICE_LEASE:
        lease = dev->data.lease;
        if (!(det_lease = virDomainLeaseRemove(vmdef, lease))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Lease %s in lockspace %s does not exist"),
                           lease->key, NULLSTR(lease->lockspace));
            return -1;
        }
        virDomainLeaseDefFree(det_lease);
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        cont = dev->data.controller;
        if ((idx = virDomainControllerFind(vmdef, cont->type,
                                           cont->idx)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("device not present in domain configuration"));
            return -1;
        }
        det_cont = virDomainControllerRemove(vmdef, idx);
        virDomainControllerDefFree(det_cont);

        break;

    case VIR_DOMAIN_DEVICE_CHR:
        if (!(chr = qemuDomainChrRemove(vmdef, dev->data.chr)))
            return -1;

        virDomainChrDefFree(chr);
        virDomainChrDefFree(dev->data.chr);
        dev->data.chr = NULL;
        break;

    case VIR_DOMAIN_DEVICE_FS:
        fs = dev->data.fs;
        idx = virDomainFSIndexByName(vmdef, fs->dst);
        if (idx < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("no matching filesystem device was found"));
            return -1;
        }

        fs = virDomainFSRemove(vmdef, idx);
        virDomainFSDefFree(fs);
        break;

    case VIR_DOMAIN_DEVICE_RNG:
        if ((idx = virDomainRNGFind(vmdef, dev->data.rng)) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("no matching RNG device was found"));
            return -1;
        }

        virDomainRNGDefFree(virDomainRNGRemove(vmdef, idx));
        break;

    case VIR_DOMAIN_DEVICE_MEMORY:
        if ((idx = virDomainMemoryFindInactiveByDef(vmdef,
                                                    dev->data.memory)) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("matching memory device was not found"));
            return -1;
        }

        virDomainMemoryDefFree(virDomainMemoryRemove(vmdef, idx));
        break;

    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("persistent detach of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }
    return 0;
}

static int
qemuDomainUpdateDeviceConfig(virQEMUCapsPtr qemuCaps,
                             virDomainDefPtr vmdef,
                             virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr orig, disk;
    virDomainGraphicsDefPtr newGraphics;
    virDomainNetDefPtr net;
    int pos;

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (!(orig = virDomainDiskByName(vmdef, disk->dst, false))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("target %s doesn't exist."), disk->dst);
            return -1;
        }
        if (!(orig->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
            !(orig->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("this disk doesn't support update"));
            return -1;
        }
        /*
         * Update 'orig'
         * We allow updating src/type//driverType/cachemode/
         */
        orig->cachemode = disk->cachemode;
        orig->startupPolicy = disk->startupPolicy;

        virStorageSourceFree(orig->src);
        orig->src = disk->src;
        disk->src = NULL;
        break;

    case VIR_DOMAIN_DEVICE_GRAPHICS:
        newGraphics = dev->data.graphics;
        pos = qemuDomainFindGraphicsIndex(vmdef, newGraphics);
        if (pos < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot find existing graphics type '%s' device to modify"),
                           virDomainGraphicsTypeToString(newGraphics->type));
            return -1;
        }

        virDomainGraphicsDefFree(vmdef->graphics[pos]);

        vmdef->graphics[pos] = newGraphics;
        dev->data.graphics = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if ((pos = virDomainNetFindIdx(vmdef, net)) < 0)
            return -1;

        virDomainNetDefFree(vmdef->nets[pos]);

        vmdef->nets[pos] = net;
        dev->data.net = NULL;

        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("persistent update of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }
    return 0;
}


static int qemuDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL, dev_copy = NULL;
    int ret = -1;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;
    virQEMUCapsPtr qemuCaps = NULL;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    virNWFilterReadLockFilterUpdates();

    cfg = virQEMUDriverGetConfig(driver);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             parse_flags);
    if (dev == NULL)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def, caps, driver->xmlopt);
        if (!dev_copy)
            goto endjob;
    }

    if (priv->qemuCaps)
        qemuCaps = virObjectRef(priv->qemuCaps);
    else if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, vm->def->emulator)))
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;

        if (virDomainDefCompatibleDevice(vmdef, dev,
                                         VIR_DOMAIN_DEVICE_ACTION_ATTACH) < 0)
            goto endjob;

        if ((ret = qemuDomainAttachDeviceConfig(qemuCaps, vmdef, dev,
                                                dom->conn)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy,
                                         VIR_DOMAIN_DEVICE_ACTION_ATTACH) < 0)
            goto endjob;

        if ((ret = qemuDomainAttachDeviceLive(vm, dev_copy, dom)) < 0)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virObjectUnref(qemuCaps);
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    virNWFilterUnlockFilterUpdates();
    return ret;
}

static int qemuDomainAttachDevice(virDomainPtr dom, const char *xml)
{
    return qemuDomainAttachDeviceFlags(dom, xml,
                                       VIR_DOMAIN_AFFECT_LIVE);
}


static int qemuDomainUpdateDeviceFlags(virDomainPtr dom,
                                       const char *xml,
                                       unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL, dev_copy = NULL;
    bool force = (flags & VIR_DOMAIN_DEVICE_MODIFY_FORCE) != 0;
    int ret = -1;
    virQEMUCapsPtr qemuCaps = NULL;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_DEVICE_MODIFY_FORCE, -1);

    virNWFilterReadLockFilterUpdates();

    cfg = virQEMUDriverGetConfig(driver);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (dev == NULL)
        goto endjob;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def, caps, driver->xmlopt);
        if (!dev_copy)
            goto endjob;
    }

    if (priv->qemuCaps)
        qemuCaps = virObjectRef(priv->qemuCaps);
    else if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, vm->def->emulator)))
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;

        if (virDomainDefCompatibleDevice(vmdef, dev,
                                         VIR_DOMAIN_DEVICE_ACTION_UPDATE) < 0)
            goto endjob;

        if ((ret = qemuDomainUpdateDeviceConfig(qemuCaps, vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy,
                                         VIR_DOMAIN_DEVICE_ACTION_UPDATE) < 0)
            goto endjob;

        if ((ret = qemuDomainUpdateDeviceLive(dom->conn, vm, dev_copy, dom, force)) < 0)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virObjectUnref(qemuCaps);
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    virNWFilterUnlockFilterUpdates();
    return ret;
}


static int qemuDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL, dev_copy = NULL;
    int ret = -1;
    unsigned int parse_flags = 0;
    virQEMUCapsPtr qemuCaps = NULL;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) &&
        !(flags & VIR_DOMAIN_AFFECT_LIVE))
        parse_flags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             parse_flags);
    if (dev == NULL)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def, caps, driver->xmlopt);
        if (!dev_copy)
            goto endjob;
    }

    if (priv->qemuCaps)
        qemuCaps = virObjectRef(priv->qemuCaps);
    else if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, vm->def->emulator)))
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;

        if (virDomainDefCompatibleDevice(vmdef, dev,
                                         VIR_DOMAIN_DEVICE_ACTION_DETACH) < 0)
            goto endjob;

        if ((ret = qemuDomainDetachDeviceConfig(vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy,
                                         VIR_DOMAIN_DEVICE_ACTION_DETACH) < 0)
            goto endjob;

        if ((ret = qemuDomainDetachDeviceLive(vm, dev_copy, dom)) < 0)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virObjectUnref(qemuCaps);
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static int qemuDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    return qemuDomainDetachDeviceFlags(dom, xml,
                                       VIR_DOMAIN_AFFECT_LIVE);
}

static int qemuDomainGetAutostart(virDomainPtr dom,
                                  int *autostart)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int qemuDomainSetAutostart(virDomainPtr dom,
                                  int autostart)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = NULL;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
            goto cleanup;

        if (!(configFile = virDomainConfigFile(cfg->configDir, vm->def->name)))
            goto endjob;

        if (!(autostartLink = virDomainConfigFile(cfg->autostartDir,
                                                  vm->def->name)))
            goto endjob;

        if (autostart) {
            if (virFileMakePath(cfg->autostartDir) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %s"),
                                     cfg->autostartDir);
                goto endjob;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s to '%s'"),
                                     autostartLink, configFile);
                goto endjob;
            }
        } else {
            if (unlink(autostartLink) < 0 &&
                errno != ENOENT &&
                errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto endjob;
            }
        }

        vm->autostart = autostart;

 endjob:
        qemuDomainObjEndJob(driver, vm);
    }
    ret = 0;

 cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


static char *qemuDomainGetSchedulerType(virDomainPtr dom,
                                        int *nparams)
{
    char *ret = NULL;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverPtr driver = dom->conn->privateData;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virQEMUDriverIsPrivileged(driver)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("CPU tuning is not available in session mode"));
        goto cleanup;
    }

    /* Domain not running, thus no cgroups - return defaults */
    if (!virDomainObjIsActive(vm)) {
        if (nparams)
            *nparams = 5;
        ignore_value(VIR_STRDUP(ret, "posix"));
        goto cleanup;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (nparams) {
        if (virCgroupSupportsCpuBW(priv->cgroup))
            *nparams = 5;
        else
            *nparams = 1;
    }

    ignore_value(VIR_STRDUP(ret, "posix"));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

/* blkioDeviceStr in the form of /device/path,weight,/device/path,weight
 * for example, /dev/disk/by-path/pci-0000:00:1f.2-scsi-0:0:0:0,800
 */
static int
qemuDomainParseBlkioDeviceStr(char *blkioDeviceStr, const char *type,
                              virBlkioDevicePtr *dev, size_t *size)
{
    char *temp;
    int ndevices = 0;
    int nsep = 0;
    size_t i;
    virBlkioDevicePtr result = NULL;

    *dev = NULL;
    *size = 0;

    if (STREQ(blkioDeviceStr, ""))
        return 0;

    temp = blkioDeviceStr;
    while (temp) {
        temp = strchr(temp, ',');
        if (temp) {
            temp++;
            nsep++;
        }
    }

    /* A valid string must have even number of fields, hence an odd
     * number of commas.  */
    if (!(nsep & 1))
        goto parse_error;

    ndevices = (nsep + 1) / 2;

    if (VIR_ALLOC_N(result, ndevices) < 0)
        return -1;

    i = 0;
    temp = blkioDeviceStr;
    while (temp) {
        char *p = temp;

        /* device path */
        p = strchr(p, ',');
        if (!p)
            goto parse_error;

        if (VIR_STRNDUP(result[i].path, temp, p - temp) < 0)
            goto cleanup;

        /* value */
        temp = p + 1;

        if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
            if (virStrToLong_uip(temp, &p, 10, &result[i].weight) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
            if (virStrToLong_uip(temp, &p, 10, &result[i].riops) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
            if (virStrToLong_uip(temp, &p, 10, &result[i].wiops) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
            if (virStrToLong_ullp(temp, &p, 10, &result[i].rbps) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
            if (virStrToLong_ullp(temp, &p, 10, &result[i].wbps) < 0)
                goto number_error;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unknown parameter '%s'"), type);
            goto cleanup;
        }

        i++;

        if (*p == '\0')
            break;
        else if (*p != ',')
            goto parse_error;
        temp = p + 1;
    }

    if (!i)
        VIR_FREE(result);

    *dev = result;
    *size = i;

    return 0;

 parse_error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("unable to parse blkio device '%s' '%s'"),
                   type, blkioDeviceStr);
    goto cleanup;

 number_error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("invalid value '%s' for parameter '%s' of device '%s'"),
                   temp, type, result[i].path);

 cleanup:
    if (result) {
        virBlkioDeviceArrayClear(result, ndevices);
        VIR_FREE(result);
    }
    return -1;
}

/* Modify dest_array to reflect all blkio device changes described in
 * src_array.  */
static int
qemuDomainMergeBlkioDevice(virBlkioDevicePtr *dest_array,
                           size_t *dest_size,
                           virBlkioDevicePtr src_array,
                           size_t src_size,
                           const char *type)
{
    size_t i, j;
    virBlkioDevicePtr dest, src;

    for (i = 0; i < src_size; i++) {
        bool found = false;

        src = &src_array[i];
        for (j = 0; j < *dest_size; j++) {
            dest = &(*dest_array)[j];
            if (STREQ(src->path, dest->path)) {
                found = true;

                if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                    dest->weight = src->weight;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                    dest->riops = src->riops;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                    dest->wiops = src->wiops;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                    dest->rbps = src->rbps;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                    dest->wbps = src->wbps;
                } else {
                    virReportError(VIR_ERR_INVALID_ARG, _("Unknown parameter %s"),
                                   type);
                    return -1;
                }
                break;
            }
        }
        if (!found) {
            if (!src->weight && !src->riops && !src->wiops && !src->rbps && !src->wbps)
                continue;
            if (VIR_EXPAND_N(*dest_array, *dest_size, 1) < 0)
                return -1;
            dest = &(*dest_array)[*dest_size - 1];

            if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                dest->weight = src->weight;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                dest->riops = src->riops;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                dest->wiops = src->wiops;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                dest->rbps = src->rbps;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                dest->wbps = src->wbps;
            } else {
                *dest_size = *dest_size - 1;
                return -1;
            }

            dest->path = src->path;
            src->path = NULL;
        }
    }

    return 0;
}

static int
qemuDomainSetBlkioParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BLKIO_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_READ_BPS,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS,
                               VIR_TYPED_PARAM_STRING,
                               NULL) < 0)
        return -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetBlkioParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!virQEMUDriverIsPrivileged(driver)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Block I/O tuning is not available in session mode"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("blkio cgroup isn't mounted"));
            goto endjob;
        }
    }

    ret = 0;
    if (def) {
        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                if (virCgroupSetBlkioWeight(priv->cgroup, param->value.ui) < 0 ||
                    virCgroupGetBlkioWeight(priv->cgroup, &def->blkio.weight) < 0)
                    ret = -1;
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                size_t ndevices;
                virBlkioDevicePtr devices = NULL;
                size_t j;

                if (qemuDomainParseBlkioDeviceStr(param->value.s,
                                                  param->field,
                                                  &devices,
                                                  &ndevices) < 0) {
                    ret = -1;
                    continue;
                }

                if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceWeight(priv->cgroup,
                                                          devices[j].path,
                                                          devices[j].weight) < 0 ||
                            virCgroupGetBlkioDeviceWeight(priv->cgroup,
                                                          devices[j].path,
                                                          &devices[j].weight) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceReadIops(priv->cgroup,
                                                            devices[j].path,
                                                            devices[j].riops) < 0 ||
                            virCgroupGetBlkioDeviceReadIops(priv->cgroup,
                                                            devices[j].path,
                                                            &devices[j].riops) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceWriteIops(priv->cgroup,
                                                             devices[j].path,
                                                             devices[j].wiops) < 0 ||
                            virCgroupGetBlkioDeviceWriteIops(priv->cgroup,
                                                             devices[j].path,
                                                             &devices[j].wiops) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceReadBps(priv->cgroup,
                                                           devices[j].path,
                                                           devices[j].rbps) < 0 ||
                            virCgroupGetBlkioDeviceReadBps(priv->cgroup,
                                                           devices[j].path,
                                                           &devices[j].rbps) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceWriteBps(priv->cgroup,
                                                            devices[j].path,
                                                            devices[j].wbps) < 0 ||
                            virCgroupGetBlkioDeviceWriteBps(priv->cgroup,
                                                            devices[j].path,
                                                            &devices[j].wbps) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else {
                    virReportError(VIR_ERR_INVALID_ARG, _("Unknown blkio parameter %s"),
                                   param->field);
                    ret = -1;
                    virBlkioDeviceArrayClear(devices, ndevices);
                    VIR_FREE(devices);

                    continue;
                }

                if (j != ndevices ||
                    qemuDomainMergeBlkioDevice(&def->blkio.devices,
                                               &def->blkio.ndevices,
                                               devices, ndevices, param->field) < 0)
                    ret = -1;
                virBlkioDeviceArrayClear(devices, ndevices);
                VIR_FREE(devices);
            }
        }

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;
    }
    if (ret < 0)
        goto endjob;
    if (persistentDef) {
        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                persistentDef->blkio.weight = param->value.ui;
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                virBlkioDevicePtr devices = NULL;
                size_t ndevices;

                if (qemuDomainParseBlkioDeviceStr(param->value.s,
                                                  param->field,
                                                  &devices,
                                                  &ndevices) < 0) {
                    ret = -1;
                    continue;
                }
                if (qemuDomainMergeBlkioDevice(&persistentDef->blkio.devices,
                                               &persistentDef->blkio.ndevices,
                                               devices, ndevices, param->field) < 0)
                    ret = -1;
                virBlkioDeviceArrayClear(devices, ndevices);
                VIR_FREE(devices);
            }
        }

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            ret = -1;
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetBlkioParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i, j;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    unsigned int val;
    int ret = -1;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We blindly return a string, and let libvirt.c and
     * remote_driver.c do the filtering on behalf of older clients
     * that can't parse it.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainGetBlkioParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virQEMUDriverIsPrivileged(driver)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Block I/O tuning is not available in session mode"));
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if ((*nparams) == 0) {
        /* Current number of blkio parameters supported by cgroups */
        *nparams = QEMU_NB_BLKIO_PARAM;
        ret = 0;
        goto cleanup;
    }

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("blkio cgroup isn't mounted"));
            goto cleanup;
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        for (i = 0; i < *nparams && i < QEMU_NB_BLKIO_PARAM; i++) {
            virTypedParameterPtr param = &params[i];
            val = 0;

            switch (i) {
            case 0: /* fill blkio weight here */
                if (virCgroupGetBlkioWeight(priv->cgroup, &val) < 0)
                    goto cleanup;
                if (virTypedParameterAssign(param, VIR_DOMAIN_BLKIO_WEIGHT,
                                            VIR_TYPED_PARAM_UINT, val) < 0)
                    goto cleanup;
                break;

            case 1: /* blkiotune.device_weight */
                if (vm->def->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < vm->def->blkio.ndevices; j++) {
                        if (!vm->def->blkio.devices[j].weight)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%u",
                                          vm->def->blkio.devices[j].path,
                                          vm->def->blkio.devices[j].weight);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                                            VIR_TYPED_PARAM_STRING,
                                            param->value.s) < 0)
                    goto cleanup;
                break;

            case 2: /* blkiotune.device_read_iops */
                if (vm->def->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < vm->def->blkio.ndevices; j++) {
                        if (!vm->def->blkio.devices[j].riops)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%u",
                                          vm->def->blkio.devices[j].path,
                                          vm->def->blkio.devices[j].riops);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS,
                                            VIR_TYPED_PARAM_STRING,
                                            param->value.s) < 0)
                    goto cleanup;
                break;

            case 3: /* blkiotune.device_write_iops */
                if (vm->def->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < vm->def->blkio.ndevices; j++) {
                        if (!vm->def->blkio.devices[j].wiops)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%u",
                                          vm->def->blkio.devices[j].path,
                                          vm->def->blkio.devices[j].wiops);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS,
                                            VIR_TYPED_PARAM_STRING,
                                            param->value.s) < 0)
                    goto cleanup;
                break;

             case 4: /* blkiotune.device_read_bps */
                if (vm->def->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < vm->def->blkio.ndevices; j++) {
                        if (!vm->def->blkio.devices[j].rbps)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%llu",
                                          vm->def->blkio.devices[j].path,
                                          vm->def->blkio.devices[j].rbps);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_BLKIO_DEVICE_READ_BPS,
                                            VIR_TYPED_PARAM_STRING,
                                            param->value.s) < 0)
                    goto cleanup;
                break;

             case 5: /* blkiotune.device_write_bps */
                if (vm->def->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < vm->def->blkio.ndevices; j++) {
                        if (!vm->def->blkio.devices[j].wbps)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%llu",
                                          vm->def->blkio.devices[j].path,
                                          vm->def->blkio.devices[j].wbps);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS,
                                            VIR_TYPED_PARAM_STRING,
                                            param->value.s) < 0)
                    goto cleanup;
                break;

            /* coverity[dead_error_begin] */
            default:
                break;
                /* should not hit here */
            }
        }
    } else if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        for (i = 0; i < *nparams && i < QEMU_NB_BLKIO_PARAM; i++) {
            virTypedParameterPtr param = &params[i];
            val = 0;
            param->value.ui = 0;
            param->type = VIR_TYPED_PARAM_UINT;

            switch (i) {
            case 0: /* fill blkio weight here */
                if (virStrcpyStatic(param->field, VIR_DOMAIN_BLKIO_WEIGHT) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Field name '%s' too long"),
                                   VIR_DOMAIN_BLKIO_WEIGHT);
                    goto cleanup;
                }
                param->value.ui = persistentDef->blkio.weight;
                break;

            case 1: /* blkiotune.device_weight */
                if (persistentDef->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < persistentDef->blkio.ndevices; j++) {
                        if (!persistentDef->blkio.devices[j].weight)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%u",
                                          persistentDef->blkio.devices[j].path,
                                          persistentDef->blkio.devices[j].weight);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (!param->value.s && VIR_STRDUP(param->value.s, "") < 0)
                    goto cleanup;
                param->type = VIR_TYPED_PARAM_STRING;
                if (virStrcpyStatic(param->field,
                                    VIR_DOMAIN_BLKIO_DEVICE_WEIGHT) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Field name '%s' too long"),
                                   VIR_DOMAIN_BLKIO_DEVICE_WEIGHT);
                    goto cleanup;
                }
                break;

            case 2: /* blkiotune.device_read_iops */
                if (persistentDef->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < persistentDef->blkio.ndevices; j++) {
                        if (!persistentDef->blkio.devices[j].riops)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%u",
                                          persistentDef->blkio.devices[j].path,
                                          persistentDef->blkio.devices[j].riops);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (!param->value.s && VIR_STRDUP(param->value.s, "") < 0)
                    goto cleanup;
                param->type = VIR_TYPED_PARAM_STRING;
                if (virStrcpyStatic(param->field,
                                    VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Field name '%s' too long"),
                                   VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS);
                    goto cleanup;
                }
                break;
            case 3: /* blkiotune.device_write_iops */
                if (persistentDef->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < persistentDef->blkio.ndevices; j++) {
                        if (!persistentDef->blkio.devices[j].wiops)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%u",
                                          persistentDef->blkio.devices[j].path,
                                          persistentDef->blkio.devices[j].wiops);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (!param->value.s && VIR_STRDUP(param->value.s, "") < 0)
                    goto cleanup;
                param->type = VIR_TYPED_PARAM_STRING;
                if (virStrcpyStatic(param->field,
                                    VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Field name '%s' too long"),
                                   VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS);
                    goto cleanup;
                }
                break;
            case 4: /* blkiotune.device_read_bps */
                if (persistentDef->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < persistentDef->blkio.ndevices; j++) {
                        if (!persistentDef->blkio.devices[j].rbps)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%llu",
                                          persistentDef->blkio.devices[j].path,
                                          persistentDef->blkio.devices[j].rbps);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (!param->value.s && VIR_STRDUP(param->value.s, "") < 0)
                    goto cleanup;
                param->type = VIR_TYPED_PARAM_STRING;
                if (virStrcpyStatic(param->field,
                                    VIR_DOMAIN_BLKIO_DEVICE_READ_BPS) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Field name '%s' too long"),
                                   VIR_DOMAIN_BLKIO_DEVICE_READ_BPS);
                    goto cleanup;
                }
                break;

            case 5: /* blkiotune.device_write_bps */
                if (persistentDef->blkio.ndevices > 0) {
                    virBuffer buf = VIR_BUFFER_INITIALIZER;
                    bool comma = false;

                    for (j = 0; j < persistentDef->blkio.ndevices; j++) {
                        if (!persistentDef->blkio.devices[j].wbps)
                            continue;
                        if (comma)
                            virBufferAddChar(&buf, ',');
                        else
                            comma = true;
                        virBufferAsprintf(&buf, "%s,%llu",
                                          persistentDef->blkio.devices[j].path,
                                          persistentDef->blkio.devices[j].wbps);
                    }
                    if (virBufferCheckError(&buf) < 0)
                        goto cleanup;
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (!param->value.s && VIR_STRDUP(param->value.s, "") < 0)
                    goto cleanup;
                param->type = VIR_TYPED_PARAM_STRING;
                if (virStrcpyStatic(param->field,
                                    VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Field name '%s' too long"),
                                   VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS);
                    goto cleanup;
                }
                break;


            /* coverity[dead_error_begin] */
            default:
                break;
                /* should not hit here */
            }
        }
    }

    if (QEMU_NB_BLKIO_PARAM < *nparams)
        *nparams = QEMU_NB_BLKIO_PARAM;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    return ret;
}

static int
qemuDomainSetMemoryParameters(virDomainPtr dom,
                              virTypedParameterPtr params,
                              int nparams,
                              unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainDefPtr persistentDef = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long long swap_hard_limit;
    unsigned long long hard_limit = 0;
    unsigned long long soft_limit = 0;
    bool set_swap_hard_limit = false;
    bool set_hard_limit = false;
    bool set_soft_limit = false;
    virQEMUDriverConfigPtr cfg = NULL;
    int rc;
    int ret = -1;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_MEMORY_HARD_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               NULL) < 0)
        return -1;


    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetMemoryParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!virQEMUDriverIsPrivileged(driver)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Memory tuning is not available in session mode"));
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup memory controller is not mounted"));
            goto endjob;
        }
    }

#define VIR_GET_LIMIT_PARAMETER(PARAM, VALUE)                                \
    if ((rc = virTypedParamsGetULLong(params, nparams, PARAM, &VALUE)) < 0)  \
        goto endjob;                                                         \
                                                                             \
    if (rc == 1)                                                             \
        set_ ## VALUE = true;

    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT, swap_hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_HARD_LIMIT, hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SOFT_LIMIT, soft_limit)

#undef VIR_GET_LIMIT_PARAMETER

    /* Swap hard limit must be greater than hard limit. */
    if (set_swap_hard_limit || set_hard_limit) {
        unsigned long long mem_limit = vm->def->mem.hard_limit;
        unsigned long long swap_limit = vm->def->mem.swap_hard_limit;

        if (set_swap_hard_limit)
            swap_limit = swap_hard_limit;

        if (set_hard_limit)
            mem_limit = hard_limit;

        if (mem_limit > swap_limit) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("memory hard_limit tunable value must be lower "
                             "than or equal to swap_hard_limit"));
            goto endjob;
        }
    }

#define QEMU_SET_MEM_PARAMETER(FUNC, VALUE)                                     \
    if (set_ ## VALUE) {                                                        \
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {                                   \
            if ((rc = FUNC(priv->cgroup, VALUE)) < 0)                           \
                goto endjob;                                                    \
            vm->def->mem.VALUE = VALUE;                                         \
        }                                                                       \
                                                                                \
        if (flags & VIR_DOMAIN_AFFECT_CONFIG)                                   \
            persistentDef->mem.VALUE = VALUE;                                   \
    }

    /* Soft limit doesn't clash with the others */
    QEMU_SET_MEM_PARAMETER(virCgroupSetMemorySoftLimit, soft_limit);

    /* set hard limit before swap hard limit if decreasing it */
    if (vm->def->mem.hard_limit > hard_limit) {
        QEMU_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);
        /* inhibit changing the limit a second time */
        set_hard_limit = false;
    }

    QEMU_SET_MEM_PARAMETER(virCgroupSetMemSwapHardLimit, swap_hard_limit);

    /* otherwise increase it after swap hard limit */
    QEMU_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);

#undef QEMU_SET_MEM_PARAMETER

    if (flags & VIR_DOMAIN_AFFECT_LIVE &&
        virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
        goto endjob;

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


#define QEMU_ASSIGN_MEM_PARAM(index, name, value)                              \
    if (index < *nparams &&                                                    \
        virTypedParameterAssign(&params[index], name, VIR_TYPED_PARAM_ULLONG,   \
                                value) < 0)                                    \
        goto cleanup

static int
qemuDomainGetMemoryParameters(virDomainPtr dom,
                              virTypedParameterPtr params,
                              int *nparams,
                              unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    unsigned long long swap_hard_limit, mem_hard_limit, mem_soft_limit;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainGetMemoryParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virQEMUDriverIsPrivileged(driver)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Memory tuning is not available in session mode"));
        goto cleanup;
    }

    if (virDomainObjGetDefs(vm, flags, NULL, &persistentDef) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = QEMU_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }

    if (persistentDef) {
        mem_hard_limit = persistentDef->mem.hard_limit;
        mem_soft_limit = persistentDef->mem.soft_limit;
        swap_hard_limit = persistentDef->mem.swap_hard_limit;
    } else {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup memory controller is not mounted"));
            goto cleanup;
        }

        if (virCgroupGetMemoryHardLimit(priv->cgroup, &mem_hard_limit) < 0)
            goto cleanup;

        if (virCgroupGetMemorySoftLimit(priv->cgroup, &mem_soft_limit) < 0)
            goto cleanup;

        if (virCgroupGetMemSwapHardLimit(priv->cgroup, &swap_hard_limit) < 0) {
            if (!virLastErrorIsSystemErrno(ENOENT) &&
                !virLastErrorIsSystemErrno(EOPNOTSUPP))
                goto cleanup;
            swap_hard_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        }
    }

    QEMU_ASSIGN_MEM_PARAM(0, VIR_DOMAIN_MEMORY_HARD_LIMIT, mem_hard_limit);
    QEMU_ASSIGN_MEM_PARAM(1, VIR_DOMAIN_MEMORY_SOFT_LIMIT, mem_soft_limit);
    QEMU_ASSIGN_MEM_PARAM(2, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT, swap_hard_limit);

    if (QEMU_NB_MEM_PARAM < *nparams)
        *nparams = QEMU_NB_MEM_PARAM;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}
#undef QEMU_ASSIGN_MEM_PARAM

static int
qemuDomainSetNumaParamsLive(virDomainObjPtr vm,
                            virBitmapPtr nodeset)
{
    virCgroupPtr cgroup_temp = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *nodeset_str = NULL;
    virDomainNumatuneMemMode mode;
    size_t i = 0;
    int ret = -1;

    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mode) == 0 &&
        mode != VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("change of nodeset for running domain "
                         "requires strict numa mode"));
        goto cleanup;
    }

    if (!virNumaNodesetIsAvailable(nodeset))
        goto cleanup;

    /* Ensure the cpuset string is formatted before passing to cgroup */
    if (!(nodeset_str = virBitmapFormat(nodeset)))
        goto cleanup;

    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &cgroup_temp) < 0 ||
        virCgroupSetCpusetMems(cgroup_temp, nodeset_str) < 0)
        goto cleanup;
    virCgroupFree(&cgroup_temp);

    for (i = 0; i < priv->nvcpupids; i++) {
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, i,
                               false, &cgroup_temp) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, nodeset_str) < 0)
            goto cleanup;
        virCgroupFree(&cgroup_temp);
    }

    for (i = 0; i < vm->def->niothreadids; i++) {
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_IOTHREAD,
                               vm->def->iothreadids[i]->iothread_id,
                               false, &cgroup_temp) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, nodeset_str) < 0)
            goto cleanup;
        virCgroupFree(&cgroup_temp);
    }

    ret = 0;
 cleanup:
    VIR_FREE(nodeset_str);
    virCgroupFree(&cgroup_temp);

    return ret;
}

static int
qemuDomainSetNumaParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = NULL;
    qemuDomainObjPrivatePtr priv;
    virBitmapPtr nodeset = NULL;
    virDomainNumatuneMemMode config_mode;
    int mode = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_NUMA_MODE,
                               VIR_TYPED_PARAM_INT,
                               VIR_DOMAIN_NUMA_NODESET,
                               VIR_TYPED_PARAM_STRING,
                               NULL) < 0)
        return -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetNumaParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_NUMA_MODE)) {
            mode = param->value.i;

            if (mode < 0 || mode >= VIR_DOMAIN_NUMATUNE_MEM_LAST) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("unsupported numatune mode: '%d'"), mode);
                goto cleanup;
            }

        } else if (STREQ(param->field, VIR_DOMAIN_NUMA_NODESET)) {
            if (virBitmapParse(param->value.s, 0, &nodeset,
                               VIR_DOMAIN_CPUMASK_LEN) < 0)
                goto cleanup;

            if (virBitmapIsAllClear(nodeset)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("Invalid nodeset of 'numatune': %s"),
                               param->value.s);
                goto cleanup;
            }
        }
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (def) {
        if (!virQEMUDriverIsPrivileged(driver)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("NUMA tuning is not available in session mode"));
            goto endjob;
        }

        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cgroup cpuset controller is not mounted"));
            goto endjob;
        }

        if (mode != -1 &&
            virDomainNumatuneGetMode(def->numa, -1, &config_mode) == 0 &&
            config_mode != mode) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("can't change numatune mode for running domain"));
            goto endjob;
        }

        if (nodeset &&
            qemuDomainSetNumaParamsLive(vm, nodeset) < 0)
            goto endjob;

        if (virDomainNumatuneSet(def->numa,
                                 def->placement_mode ==
                                 VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                 -1, mode, nodeset) < 0)
            goto endjob;

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;
    }

    if (persistentDef) {
        if (virDomainNumatuneSet(persistentDef->numa,
                                 persistentDef->placement_mode ==
                                 VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                 -1, mode, nodeset) < 0)
            goto endjob;

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virBitmapFree(nodeset);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetNumaParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainNumatuneMemMode tmpmode = VIR_DOMAIN_NUMATUNE_MEM_STRICT;
    qemuDomainObjPrivatePtr priv;
    char *nodeset = NULL;
    int ret = -1;
    virDomainDefPtr def = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;
    priv = vm->privateData;

    if (virDomainGetNumaParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if ((*nparams) == 0) {
        *nparams = QEMU_NB_NUMA_PARAM;
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < QEMU_NB_NUMA_PARAM && i < *nparams; i++) {
        virMemoryParameterPtr param = &params[i];

        switch (i) {
        case 0: /* fill numa mode here */
            ignore_value(virDomainNumatuneGetMode(def->numa, -1, &tmpmode));

            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_MODE,
                                        VIR_TYPED_PARAM_INT, tmpmode) < 0)
                goto cleanup;

            break;

        case 1: /* fill numa nodeset here */
            nodeset = virDomainNumatuneFormatNodeset(def->numa,
                                                     priv->autoNodeset, -1);
            if (!nodeset ||
                virTypedParameterAssign(param, VIR_DOMAIN_NUMA_NODESET,
                                        VIR_TYPED_PARAM_STRING, nodeset) < 0)
                goto cleanup;

            nodeset = NULL;
            break;

        /* coverity[dead_error_begin] */
        default:
            break;
            /* should not hit here */
        }
    }

    if (*nparams > QEMU_NB_NUMA_PARAM)
        *nparams = QEMU_NB_NUMA_PARAM;
    ret = 0;

 cleanup:
    VIR_FREE(nodeset);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuSetVcpusBWLive(virDomainObjPtr vm, virCgroupPtr cgroup,
                   unsigned long long period, long long quota)
{
    size_t i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup_vcpu = NULL;

    if (period == 0 && quota == 0)
        return 0;

    if (!qemuDomainHasVcpuPids(vm))
        return 0;

    for (i = 0; i < priv->nvcpupids; i++) {
        if (virCgroupNewThread(cgroup, VIR_CGROUP_THREAD_VCPU, i,
                               false, &cgroup_vcpu) < 0)
            goto cleanup;

        if (qemuSetupCgroupVcpuBW(cgroup_vcpu, period, quota) < 0)
            goto cleanup;

        virCgroupFree(&cgroup_vcpu);
    }

    return 0;

 cleanup:
    virCgroupFree(&cgroup_vcpu);
    return -1;
}

static int
qemuSetEmulatorBandwidthLive(virCgroupPtr cgroup,
                             unsigned long long period,
                             long long quota)
{
    virCgroupPtr cgroup_emulator = NULL;

    if (period == 0 && quota == 0)
        return 0;

    if (virCgroupNewThread(cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &cgroup_emulator) < 0)
        goto cleanup;

    if (qemuSetupCgroupVcpuBW(cgroup_emulator, period, quota) < 0)
        goto cleanup;

    virCgroupFree(&cgroup_emulator);
    return 0;

 cleanup:
    virCgroupFree(&cgroup_emulator);
    return -1;
}

#define SCHED_RANGE_CHECK(VAR, NAME, MIN, MAX)                              \
    if (((VAR) > 0 && (VAR) < (MIN)) || (VAR) > (MAX)) {                    \
        virReportError(VIR_ERR_INVALID_ARG,                                 \
                       _("value of '%s' is out of range [%lld, %lld]"),     \
                       NAME, MIN, MAX);                                     \
        rc = -1;                                                            \
        goto endjob;                                                        \
    }

static int
qemuDomainSetSchedulerParametersFlags(virDomainPtr dom,
                                      virTypedParameterPtr params,
                                      int nparams,
                                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    unsigned long long value_ul;
    long long value_l;
    int ret = -1;
    int rc;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv;
    virObjectEventPtr event = NULL;
    virTypedParameterPtr eventParams = NULL;
    int eventNparams = 0;
    int eventMaxNparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_CPU_SHARES,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_SCHEDULER_VCPU_PERIOD,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_SCHEDULER_VCPU_QUOTA,
                               VIR_TYPED_PARAM_LLONG,
                               VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA,
                               VIR_TYPED_PARAM_LLONG,
                               NULL) < 0)
        return -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!virQEMUDriverIsPrivileged(driver)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("CPU tuning is not available in session mode"));
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &vmdef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup CPU controller is not mounted"));
            goto endjob;
        }
    }

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];
        value_ul = param->value.ul;
        value_l = param->value.l;

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CPU_SHARES)) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                unsigned long long val;
                if (virCgroupSetCpuShares(priv->cgroup, value_ul) < 0)
                    goto endjob;

                if (virCgroupGetCpuShares(priv->cgroup, &val) < 0)
                    goto endjob;

                vm->def->cputune.shares = val;
                vm->def->cputune.sharesSpecified = true;

                if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                            &eventMaxNparams,
                                            VIR_DOMAIN_TUNABLE_CPU_CPU_SHARES,
                                            val) < 0)
                    goto endjob;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.shares = value_ul;
                vmdef->cputune.sharesSpecified = true;
            }


        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_PERIOD)) {
            SCHED_RANGE_CHECK(value_ul, VIR_DOMAIN_SCHEDULER_VCPU_PERIOD,
                              QEMU_SCHED_MIN_PERIOD, QEMU_SCHED_MAX_PERIOD);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_ul) {
                if ((rc = qemuSetVcpusBWLive(vm, priv->cgroup, value_ul, 0)))
                    goto endjob;

                vm->def->cputune.period = value_ul;

                if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                            &eventMaxNparams,
                                            VIR_DOMAIN_TUNABLE_CPU_VCPU_PERIOD,
                                            value_ul) < 0)
                    goto endjob;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.period = params[i].value.ul;

        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_QUOTA)) {
            SCHED_RANGE_CHECK(value_l, VIR_DOMAIN_SCHEDULER_VCPU_QUOTA,
                              QEMU_SCHED_MIN_QUOTA, QEMU_SCHED_MAX_QUOTA);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_l) {
                if ((rc = qemuSetVcpusBWLive(vm, priv->cgroup, 0, value_l)))
                    goto endjob;

                vm->def->cputune.quota = value_l;

                if (virTypedParamsAddLLong(&eventParams, &eventNparams,
                                           &eventMaxNparams,
                                           VIR_DOMAIN_TUNABLE_CPU_VCPU_QUOTA,
                                           value_l) < 0)
                    goto endjob;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.quota = value_l;

        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD)) {
            SCHED_RANGE_CHECK(value_ul, VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD,
                              QEMU_SCHED_MIN_PERIOD, QEMU_SCHED_MAX_PERIOD);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_ul) {
                if ((rc = qemuSetEmulatorBandwidthLive(priv->cgroup,
                                                       value_ul, 0)))
                    goto endjob;

                vm->def->cputune.emulator_period = value_ul;

                if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                            &eventMaxNparams,
                                            VIR_DOMAIN_TUNABLE_CPU_EMULATOR_PERIOD,
                                            value_ul) < 0)
                    goto endjob;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.emulator_period = value_ul;

        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA)) {
            SCHED_RANGE_CHECK(value_l, VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA,
                              QEMU_SCHED_MIN_QUOTA, QEMU_SCHED_MAX_QUOTA);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_l) {
                if ((rc = qemuSetEmulatorBandwidthLive(priv->cgroup,
                                                       0, value_l)))
                    goto endjob;

                vm->def->cputune.emulator_quota = value_l;

                if (virTypedParamsAddLLong(&eventParams, &eventNparams,
                                           &eventMaxNparams,
                                           VIR_DOMAIN_TUNABLE_CPU_EMULATOR_QUOTA,
                                           value_l) < 0)
                    goto endjob;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.emulator_quota = value_l;
        }
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;

    if (eventNparams) {
        event = virDomainEventTunableNewFromDom(dom, eventParams, eventNparams);
        eventNparams = 0;
        qemuDomainEventQueue(driver, event);
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        rc = virDomainSaveConfig(cfg->configDir, vmdef);
        if (rc < 0)
            goto endjob;

        virDomainObjAssignDef(vm, vmdef, false, NULL);
        vmdef = NULL;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(vmdef);
    virDomainObjEndAPI(&vm);
    if (eventNparams)
        virTypedParamsFree(eventParams, eventNparams);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}
#undef SCHED_RANGE_CHECK

static int
qemuDomainSetSchedulerParameters(virDomainPtr dom,
                                 virTypedParameterPtr params,
                                 int nparams)
{
    return qemuDomainSetSchedulerParametersFlags(dom,
                                                 params,
                                                 nparams,
                                                 VIR_DOMAIN_AFFECT_CURRENT);
}

static int
qemuGetVcpuBWLive(virCgroupPtr cgroup, unsigned long long *period,
                  long long *quota)
{
    if (virCgroupGetCpuCfsPeriod(cgroup, period) < 0)
        return -1;

    if (virCgroupGetCpuCfsQuota(cgroup, quota) < 0)
        return -1;

    return 0;
}

static int
qemuGetVcpusBWLive(virDomainObjPtr vm,
                   unsigned long long *period, long long *quota)
{
    virCgroupPtr cgroup_vcpu = NULL;
    qemuDomainObjPrivatePtr priv = NULL;
    int rc;
    int ret = -1;

    priv = vm->privateData;
    if (!qemuDomainHasVcpuPids(vm)) {
        /* We do not create sub dir for each vcpu */
        rc = qemuGetVcpuBWLive(priv->cgroup, period, quota);
        if (rc < 0)
            goto cleanup;

        if (*quota > 0)
            *quota /= virDomainDefGetVcpus(vm->def);
        goto out;
    }

    /* get period and quota for vcpu0 */
    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, 0,
                           false, &cgroup_vcpu) < 0)
        goto cleanup;

    rc = qemuGetVcpuBWLive(cgroup_vcpu, period, quota);
    if (rc < 0)
        goto cleanup;

 out:
    ret = 0;

 cleanup:
    virCgroupFree(&cgroup_vcpu);
    return ret;
}

static int
qemuGetEmulatorBandwidthLive(virCgroupPtr cgroup,
                             unsigned long long *period,
                             long long *quota)
{
    virCgroupPtr cgroup_emulator = NULL;
    int ret = -1;

    /* get period and quota for emulator */
    if (virCgroupNewThread(cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &cgroup_emulator) < 0)
        goto cleanup;

    if (qemuGetVcpuBWLive(cgroup_emulator, period, quota) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCgroupFree(&cgroup_emulator);
    return ret;
}

static int
qemuDomainGetSchedulerParametersFlags(virDomainPtr dom,
                                      virTypedParameterPtr params,
                                      int *nparams,
                                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    unsigned long long shares;
    unsigned long long period;
    long long quota;
    unsigned long long emulator_period;
    long long emulator_quota;
    int ret = -1;
    int rc;
    bool cpu_bw_status = false;
    int saved_nparams = 0;
    virDomainDefPtr persistentDef;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virQEMUDriverIsPrivileged(driver)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("CPU tuning is not available in session mode"));
        goto cleanup;
    }

    if (*nparams > 1)
        cpu_bw_status = virCgroupSupportsCpuBW(priv->cgroup);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        shares = persistentDef->cputune.shares;
        if (*nparams > 1) {
            period = persistentDef->cputune.period;
            quota = persistentDef->cputune.quota;
            emulator_period = persistentDef->cputune.emulator_period;
            emulator_quota = persistentDef->cputune.emulator_quota;
            cpu_bw_status = true; /* Allow copy of data to params[] */
        }
        goto out;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (virCgroupGetCpuShares(priv->cgroup, &shares) < 0)
        goto cleanup;

    if (*nparams > 1 && cpu_bw_status) {
        rc = qemuGetVcpusBWLive(vm, &period, &quota);
        if (rc != 0)
            goto cleanup;
    }

    if (*nparams > 3 && cpu_bw_status) {
        rc = qemuGetEmulatorBandwidthLive(priv->cgroup, &emulator_period,
                                          &emulator_quota);
        if (rc != 0)
            goto cleanup;
    }

 out:
    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_CPU_SHARES,
                                VIR_TYPED_PARAM_ULLONG, shares) < 0)
        goto cleanup;
    saved_nparams++;

    if (cpu_bw_status) {
        if (*nparams > saved_nparams) {
            if (virTypedParameterAssign(&params[1],
                                        VIR_DOMAIN_SCHEDULER_VCPU_PERIOD,
                                        VIR_TYPED_PARAM_ULLONG, period) < 0)
                goto cleanup;
            saved_nparams++;
        }

        if (*nparams > saved_nparams) {
            if (virTypedParameterAssign(&params[2],
                                        VIR_DOMAIN_SCHEDULER_VCPU_QUOTA,
                                        VIR_TYPED_PARAM_LLONG, quota) < 0)
                goto cleanup;
            saved_nparams++;
        }

        if (*nparams > saved_nparams) {
            if (virTypedParameterAssign(&params[3],
                                        VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD,
                                        VIR_TYPED_PARAM_ULLONG,
                                        emulator_period) < 0)
                goto cleanup;
            saved_nparams++;
        }

        if (*nparams > saved_nparams) {
            if (virTypedParameterAssign(&params[4],
                                        VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA,
                                        VIR_TYPED_PARAM_LLONG,
                                        emulator_quota) < 0)
                goto cleanup;
            saved_nparams++;
        }
    }

    *nparams = saved_nparams;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    return ret;
}

static int
qemuDomainGetSchedulerParameters(virDomainPtr dom,
                                 virTypedParameterPtr params,
                                 int *nparams)
{
    return qemuDomainGetSchedulerParametersFlags(dom, params, nparams,
                                                 VIR_DOMAIN_AFFECT_CURRENT);
}

/**
 * Resize a block device while a guest is running. Resize to a lower size
 * is supported, but should be used with extreme caution.  Note that it
 * only supports to resize image files, it can't resize block devices
 * like LVM volumes.
 */
static int
qemuDomainBlockResize(virDomainPtr dom,
                      const char *path,
                      unsigned long long size,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;
    char *device = NULL;
    virDomainDiskDefPtr disk = NULL;

    virCheckFlags(VIR_DOMAIN_BLOCK_RESIZE_BYTES, -1);

    if (path[0] == '\0') {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("empty path"));
        return -1;
    }

    /* We prefer operating on bytes.  */
    if ((flags & VIR_DOMAIN_BLOCK_RESIZE_BYTES) == 0) {
        if (size > ULLONG_MAX / 1024) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("size must be less than %llu"),
                           ULLONG_MAX / 1024);
            return -1;
        }
        size *= 1024;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainBlockResizeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!(disk = virDomainDiskByName(vm->def, path, false))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path: %s"), path);
        goto endjob;
    }

    /* qcow2 and qed must be sized on 512 byte blocks/sectors,
     * so adjust size if necessary to round up.
     */
    if (disk->src->format == VIR_STORAGE_FILE_QCOW2 ||
        disk->src->format == VIR_STORAGE_FILE_QED)
        size = VIR_ROUND_UP(size, 512);

    if (virAsprintf(&device, "%s%s", QEMU_DRIVE_HOST_PREFIX,
                    disk->info.alias) < 0)
        goto endjob;

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorBlockResize(priv->mon, device, size) < 0) {
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        goto endjob;
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto endjob;

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(device);
    virDomainObjEndAPI(&vm);
    return ret;
}


static void
qemuDomainBlockStatsGatherTotals(void *payload,
                                 const void *name ATTRIBUTE_UNUSED,
                                 void *opaque)
{
    qemuBlockStatsPtr data = payload;
    qemuBlockStatsPtr total = opaque;

#define QEMU_BLOCK_STAT_TOTAL(NAME)                                            \
    if (data->NAME > 0)                                                        \
        total->NAME += data->NAME

    QEMU_BLOCK_STAT_TOTAL(wr_bytes);
    QEMU_BLOCK_STAT_TOTAL(wr_req);
    QEMU_BLOCK_STAT_TOTAL(rd_bytes);
    QEMU_BLOCK_STAT_TOTAL(rd_req);
    QEMU_BLOCK_STAT_TOTAL(flush_req);
    QEMU_BLOCK_STAT_TOTAL(wr_total_times);
    QEMU_BLOCK_STAT_TOTAL(rd_total_times);
    QEMU_BLOCK_STAT_TOTAL(flush_total_times);
#undef QEMU_BLOCK_STAT_TOTAL
}


/**
 * qemuDomainBlocksStatsGather:
 * @driver: driver object
 * @vm: domain object
 * @path: to gather the statistics for
 * @retstats: returns pointer to structure holding the stats
 *
 * Gathers the block statistics for use in qemuDomainBlockStats* APIs.
 *
 * Returns -1 on error; number of filled block statistics on success.
 */
static int
qemuDomainBlocksStatsGather(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            const char *path,
                            qemuBlockStatsPtr *retstats)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDiskDefPtr disk;
    virHashTablePtr blockstats = NULL;
    qemuBlockStatsPtr stats;
    int nstats;
    char *diskAlias = NULL;
    int ret = -1;

    if (*path) {
        if (!(disk = virDomainDiskByName(vm->def, path, false))) {
            virReportError(VIR_ERR_INVALID_ARG, _("invalid path: %s"), path);
            goto cleanup;
        }

        if (!disk->info.alias) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing disk device alias name for %s"), disk->dst);
            goto cleanup;
        }

        if (VIR_STRDUP(diskAlias, disk->info.alias) < 0)
            goto cleanup;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    nstats = qemuMonitorGetAllBlockStatsInfo(priv->mon, &blockstats, false);
    if (qemuDomainObjExitMonitor(driver, vm) < 0 || nstats < 0)
        goto cleanup;

    if (VIR_ALLOC(*retstats) < 0)
        goto cleanup;

    if (diskAlias) {
        if (!(stats = virHashLookup(blockstats, diskAlias))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot find statistics for device '%s'"), diskAlias);
            goto cleanup;
        }

        **retstats = *stats;
    } else {
        virHashForEach(blockstats, qemuDomainBlockStatsGatherTotals, *retstats);
    }

    ret = nstats;

 cleanup:
    VIR_FREE(diskAlias);
    virHashFree(blockstats);
    return ret;
}


/* This uses the 'info blockstats' monitor command which was
 * integrated into both qemu & kvm in late 2007.  If the command is
 * not supported we detect this and return the appropriate error.
 */
static int
qemuDomainBlockStats(virDomainPtr dom,
                     const char *path,
                     virDomainBlockStatsPtr stats)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuBlockStatsPtr blockstats = NULL;
    int ret = -1;
    virDomainObjPtr vm;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainBlockStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (qemuDomainBlocksStatsGather(driver, vm, path, &blockstats) < 0)
        goto endjob;

    stats->rd_req = blockstats->rd_req;
    stats->rd_bytes = blockstats->rd_bytes;
    stats->wr_req = blockstats->wr_req;
    stats->wr_bytes = blockstats->wr_bytes;
    /* qemu doesn't report the error count */
    stats->errs = -1;

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    VIR_FREE(blockstats);
    return ret;
}


static int
qemuDomainBlockStatsFlags(virDomainPtr dom,
                          const char *path,
                          virTypedParameterPtr params,
                          int *nparams,
                          unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuBlockStatsPtr blockstats = NULL;
    int nstats;
    int ret = -1;

    VIR_DEBUG("params=%p, flags=%x", params, flags);

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainBlockStatsFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if ((nstats = qemuDomainBlocksStatsGather(driver, vm, path,
                                              &blockstats)) < 0)
        goto endjob;

    /* return count of supported stats */
    if (*nparams == 0) {
        *nparams = nstats;
        ret = 0;
        goto endjob;
    }

    nstats = 0;

#define QEMU_BLOCK_STATS_ASSIGN_PARAM(VAR, NAME)                              \
    if (nstats < *nparams && (blockstats->VAR) != -1) {                       \
        if (virTypedParameterAssign(params + nstats, NAME,                    \
                                    VIR_TYPED_PARAM_LLONG, (blockstats->VAR)) < 0) \
            goto endjob;                                                      \
        nstats++;                                                             \
    }

    QEMU_BLOCK_STATS_ASSIGN_PARAM(wr_bytes, VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES);
    QEMU_BLOCK_STATS_ASSIGN_PARAM(wr_req, VIR_DOMAIN_BLOCK_STATS_WRITE_REQ);

    QEMU_BLOCK_STATS_ASSIGN_PARAM(rd_bytes, VIR_DOMAIN_BLOCK_STATS_READ_BYTES);
    QEMU_BLOCK_STATS_ASSIGN_PARAM(rd_req, VIR_DOMAIN_BLOCK_STATS_READ_REQ);

    QEMU_BLOCK_STATS_ASSIGN_PARAM(flush_req, VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ);

    QEMU_BLOCK_STATS_ASSIGN_PARAM(wr_total_times,
                                  VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES);
    QEMU_BLOCK_STATS_ASSIGN_PARAM(rd_total_times,
                                  VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES);
    QEMU_BLOCK_STATS_ASSIGN_PARAM(flush_total_times,
                                  VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES);
#undef QEMU_BLOCK_STATS_ASSIGN_PARAM

    ret = 0;
    *nparams = nstats;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(blockstats);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainInterfaceStats(virDomainPtr dom,
                         const char *path,
                         virDomainInterfaceStatsPtr stats)
{
    virDomainObjPtr vm;
    size_t i;
    int ret = -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainInterfaceStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    /* Check the path is one of the domain's network interfaces. */
    for (i = 0; i < vm->def->nnets; i++) {
        if (vm->def->nets[i]->ifname &&
            STREQ(vm->def->nets[i]->ifname, path)) {
            ret = 0;
            break;
        }
    }

    if (ret == 0)
        ret = virNetInterfaceStats(path, stats);
    else
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path, '%s' is not a known interface"), path);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainSetInterfaceParameters(virDomainPtr dom,
                                 const char *device,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1;
    virDomainNetDefPtr net = NULL, persistentNet = NULL;
    virNetDevBandwidthPtr bandwidth = NULL, newBandwidth = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    bool inboundSpecified = false, outboundSpecified = false;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BANDWIDTH_IN_AVERAGE,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_IN_PEAK,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_IN_BURST,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_IN_FLOOR,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_OUT_PEAK,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_OUT_BURST,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetInterfaceParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (def &&
        !(net = virDomainNetFind(vm->def, device))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find device %s"), device);
        goto endjob;
    }

    if (persistentDef &&
        !(persistentNet = virDomainNetFind(persistentDef, device))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find device %s"), device);
        goto endjob;
    }

    if ((VIR_ALLOC(bandwidth) < 0) ||
        (VIR_ALLOC(bandwidth->in) < 0) ||
        (VIR_ALLOC(bandwidth->out) < 0))
        goto endjob;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_IN_AVERAGE)) {
            bandwidth->in->average = params[i].value.ui;
            inboundSpecified = true;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_IN_PEAK)) {
            bandwidth->in->peak = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_IN_BURST)) {
            bandwidth->in->burst = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_IN_FLOOR)) {
            bandwidth->in->floor = params[i].value.ui;
            inboundSpecified = true;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE)) {
            bandwidth->out->average = params[i].value.ui;
            outboundSpecified = true;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_OUT_PEAK)) {
            bandwidth->out->peak = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_OUT_BURST)) {
            bandwidth->out->burst = params[i].value.ui;
        }
    }

    /* average or floor are mandatory, peak and burst are optional.
     * So if no average or floor is given, we free inbound/outbound
     * here which causes inbound/outbound to not be set. */
    if (!bandwidth->in->average && !bandwidth->in->floor)
        VIR_FREE(bandwidth->in);
    if (!bandwidth->out->average)
        VIR_FREE(bandwidth->out);

    if (net) {
        if (VIR_ALLOC(newBandwidth) < 0)
            goto endjob;

        /* virNetDevBandwidthSet() will clear any previous value of
         * bandwidth parameters, so merge with old bandwidth parameters
         * here to prevent them from being lost. */
        if (bandwidth->in ||
            (!inboundSpecified && net->bandwidth && net->bandwidth->in)) {
            if (VIR_ALLOC(newBandwidth->in) < 0)
                goto endjob;

            memcpy(newBandwidth->in,
                   bandwidth->in ? bandwidth->in : net->bandwidth->in,
                   sizeof(*newBandwidth->in));
        }
        if (bandwidth->out ||
            (!outboundSpecified && net->bandwidth && net->bandwidth->out)) {
            if (VIR_ALLOC(newBandwidth->out) < 0)
                goto endjob;

            memcpy(newBandwidth->out,
                   bandwidth->out ? bandwidth->out : net->bandwidth->out,
                   sizeof(*newBandwidth->out));
        }

        if (!networkBandwidthChangeAllowed(net, newBandwidth))
            goto endjob;

        if (virNetDevBandwidthSet(net->ifname, newBandwidth, false) < 0 ||
            networkBandwidthUpdate(net, newBandwidth) < 0) {
            ignore_value(virNetDevBandwidthSet(net->ifname,
                                               net->bandwidth,
                                               false));
            goto endjob;
        }

        virNetDevBandwidthFree(net->bandwidth);
        if (newBandwidth->in || newBandwidth->out) {
            net->bandwidth = newBandwidth;
            newBandwidth = NULL;
        } else {
            net->bandwidth = NULL;
        }

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            virNetDevBandwidthFree(net->data.network.actual->bandwidth);
            if (virNetDevBandwidthCopy(&net->data.network.actual->bandwidth,
                                       net->bandwidth) < 0)
                goto endjob;
        }

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto endjob;
    }

    if (persistentNet) {
        if (!persistentNet->bandwidth) {
            persistentNet->bandwidth = bandwidth;
            bandwidth = NULL;
        } else {
            if (bandwidth->in) {
                VIR_FREE(persistentNet->bandwidth->in);
                persistentNet->bandwidth->in = bandwidth->in;
                bandwidth->in = NULL;
            } else  if (inboundSpecified) {
                VIR_FREE(persistentNet->bandwidth->in);
            }
            if (bandwidth->out) {
                VIR_FREE(persistentNet->bandwidth->out);
                persistentNet->bandwidth->out = bandwidth->out;
                bandwidth->out = NULL;
            } else if (outboundSpecified) {
                VIR_FREE(persistentNet->bandwidth->out);
            }
        }

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virNetDevBandwidthFree(bandwidth);
    virNetDevBandwidthFree(newBandwidth);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetInterfaceParameters(virDomainPtr dom,
                                 const char *device,
                                 virTypedParameterPtr params,
                                 int *nparams,
                                 unsigned int flags)
{
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainNetDefPtr net = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetInterfaceParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if ((*nparams) == 0) {
        *nparams = QEMU_NB_BANDWIDTH_PARAM;
        ret = 0;
        goto cleanup;
    }

    net = virDomainNetFind(def, device);
    if (!net) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find device %s"), device);
        goto cleanup;
    }

    for (i = 0; i < *nparams && i < QEMU_NB_BANDWIDTH_PARAM; i++) {
        switch (i) {
        case 0: /* inbound.average */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_IN_AVERAGE,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->in)
                params[i].value.ui = net->bandwidth->in->average;
            break;
        case 1: /* inbound.peak */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_IN_PEAK,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->in)
                params[i].value.ui = net->bandwidth->in->peak;
            break;
        case 2: /* inbound.burst */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_IN_BURST,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->in)
                params[i].value.ui = net->bandwidth->in->burst;
            break;
        case 3: /* inbound.floor */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_IN_FLOOR,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->in)
                params[i].value.ui = net->bandwidth->in->floor;
            break;
        case 4: /* outbound.average */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->out)
                params[i].value.ui = net->bandwidth->out->average;
            break;
        case 5: /* outbound.peak */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_OUT_PEAK,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->out)
                params[i].value.ui = net->bandwidth->out->peak;
            break;
        case 6: /* outbound.burst */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_OUT_BURST,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->out)
                params[i].value.ui = net->bandwidth->out->burst;
            break;
        /* coverity[dead_error_begin] */
        default:
            break;
            /* should not hit here */
        }
    }

    if (*nparams > QEMU_NB_BANDWIDTH_PARAM)
        *nparams = QEMU_NB_BANDWIDTH_PARAM;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainMemoryStats(virDomainPtr dom,
                      virDomainMemoryStatPtr stats,
                      unsigned int nr_stats,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;
    long rss;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMemoryStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (vm->def->memballoon &&
        vm->def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO) {
        priv = vm->privateData;
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorGetMemoryStats(priv->mon, stats, nr_stats);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;

        if (ret < 0 || ret >= nr_stats)
            goto endjob;
    } else {
        ret = 0;
    }

    if (qemuGetProcessInfo(NULL, NULL, &rss, vm->pid, 0) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("cannot get RSS for domain"));
    } else {
        stats[ret].tag = VIR_DOMAIN_MEMORY_STAT_RSS;
        stats[ret].val = rss;
        ret++;
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainBlockPeek(virDomainPtr dom,
                    const char *path,
                    unsigned long long offset, size_t size,
                    void *buffer,
                    unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int fd = -1, ret = -1;
    const char *actual;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainBlockPeekEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    /* Check the path belongs to this domain.  */
    if (!(actual = virDomainDiskPathByName(vm->def, path))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path '%s'"), path);
        goto cleanup;
    }
    path = actual;

    fd = qemuOpenFile(driver, vm, path, O_RDONLY, NULL, NULL);
    if (fd == -1)
        goto cleanup;

    /* Seek and read. */
    /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
     * be 64 bits on all platforms.
     */
    if (lseek(fd, offset, SEEK_SET) == (off_t) -1 ||
        saferead(fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError(errno,
                             _("%s: failed to seek or read"), path);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainMemoryPeek(virDomainPtr dom,
                     unsigned long long offset, size_t size,
                     void *buffer,
                     unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *tmp = NULL;
    int fd = -1, ret = -1;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_MEMORY_VIRTUAL | VIR_MEMORY_PHYSICAL, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainMemoryPeekEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (flags != VIR_MEMORY_VIRTUAL && flags != VIR_MEMORY_PHYSICAL) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("flags parameter must be VIR_MEMORY_VIRTUAL or VIR_MEMORY_PHYSICAL"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (virAsprintf(&tmp, "%s/qemu.mem.XXXXXX", cfg->cacheDir) < 0)
        goto endjob;

    /* Create a temporary filename. */
    if ((fd = mkostemp(tmp, O_CLOEXEC)) == -1) {
        virReportSystemError(errno,
                             _("mkostemp(\"%s\") failed"), tmp);
        goto endjob;
    }

    virSecurityManagerSetSavedStateLabel(qemu_driver->securityManager, vm->def, tmp);

    priv = vm->privateData;
    qemuDomainObjEnterMonitor(driver, vm);
    if (flags == VIR_MEMORY_VIRTUAL) {
        if (qemuMonitorSaveVirtualMemory(priv->mon, offset, size, tmp) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto endjob;
        }
    } else {
        if (qemuMonitorSavePhysicalMemory(priv->mon, offset, size, tmp) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto endjob;
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto endjob;

    /* Read the memory file into buffer. */
    if (saferead(fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError(errno,
                             _("failed to read temporary file "
                               "created with template %s"), tmp);
        goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FORCE_CLOSE(fd);
    if (tmp)
        unlink(tmp);
    VIR_FREE(tmp);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


/* Refresh the capacity and allocation limits of a given storage
 * source.  Assumes that the caller has already obtained a domain
 * job. */
static int
qemuStorageLimitsRefresh(virQEMUDriverPtr driver,
                         virQEMUDriverConfigPtr cfg,
                         virDomainObjPtr vm,
                         virStorageSourcePtr src)
{
    int ret = -1;
    int fd = -1;
    off_t end;
    virStorageSourcePtr meta = NULL;
    struct stat sb;
    int format;
    char *buf = NULL;
    ssize_t len;

    /* FIXME: For an offline domain, we always want to check current
     * on-disk statistics (as users have been known to change offline
     * images behind our backs).  For a running domain, however, it
     * would be nice to avoid opening a file (particularly since
     * reading a file while qemu is writing it risks the reader seeing
     * bogus data), or even avoid a stat, if the information
     * remembered from the previous run is still viable.
     *
     * For read-only disks, nothing should be changing unless the user
     * has requested a block-commit action.  For read-write disks, we
     * know some special cases: capacity should not change without a
     * block-resize (where capacity is the only stat that requires
     * reading a file, and even then, only for non-raw files); and
     * physical size of a raw image or of a block device should
     * likewise not be changing without block-resize.  On the other
     * hand, allocation of a raw file can change (if the file is
     * sparse, but the amount of sparseness changes due to writes or
     * punching holes), and physical size of a non-raw file can
     * change.
     */
    if (virStorageSourceIsLocalStorage(src)) {
        if ((fd = qemuOpenFile(driver, vm, src->path, O_RDONLY,
                               NULL, NULL)) == -1)
            goto cleanup;

        if (fstat(fd, &sb) < 0) {
            virReportSystemError(errno,
                                 _("cannot stat file '%s'"), src->path);
            goto cleanup;
        }

        if ((len = virFileReadHeaderFD(fd, VIR_STORAGE_MAX_HEADER, &buf)) < 0) {
            virReportSystemError(errno, _("cannot read header '%s'"),
                                 src->path);
            goto cleanup;
        }
    } else {
        if (virStorageFileInitAs(src, cfg->user, cfg->group) < 0)
            goto cleanup;

        if ((len = virStorageFileReadHeader(src, VIR_STORAGE_MAX_HEADER,
                                            &buf)) < 0)
            goto cleanup;

        if (virStorageFileStat(src, &sb) < 0) {
            virReportSystemError(errno, _("failed to stat remote file '%s'"),
                                 NULLSTR(src->path));
            goto cleanup;
        }
    }

    /* Get info for normal formats */
    if (S_ISREG(sb.st_mode) || fd == -1) {
#ifndef WIN32
        src->allocation = (unsigned long long)sb.st_blocks *
            (unsigned long long)DEV_BSIZE;
#else
        src->allocation = sb.st_size;
#endif
        /* Allocation tracks when the file is sparse, physical is the
         * last offset of the file. */
        src->physical = sb.st_size;
    } else {
        /* NB. Because we configure with AC_SYS_LARGEFILE, off_t
         * should be 64 bits on all platforms.  For block devices, we
         * have to seek (safe even if someone else is writing) to
         * determine physical size, and assume that allocation is the
         * same as physical (but can refine that assumption later if
         * qemu is still running).
         */
        end = lseek(fd, 0, SEEK_END);
        if (end == (off_t)-1) {
            virReportSystemError(errno,
                                 _("failed to seek to end of %s"), src->path);
            goto cleanup;
        }
        src->physical = end;
        src->allocation = end;
    }

    /* Raw files: capacity is physical size.  For all other files: if
     * the metadata has a capacity, use that, otherwise fall back to
     * physical size.  */
    if (!(format = src->format)) {
        if (!cfg->allowDiskFormatProbing) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("no disk format for %s and probing is disabled"),
                           src->path);
            goto cleanup;
        }

        if ((format = virStorageFileProbeFormatFromBuf(src->path,
                                                       buf, len)) < 0)
            goto cleanup;
    }
    if (format == VIR_STORAGE_FILE_RAW)
        src->capacity = src->physical;
    else if ((meta = virStorageFileGetMetadataFromBuf(src->path, buf,
                                                      len, format, NULL)))
        src->capacity = meta->capacity ? meta->capacity : src->physical;
    else
        goto cleanup;

    /* If guest is not using raw disk format and is on a host block
     * device, then leave the value unspecified, so caller knows to
     * query the highest allocated extent from QEMU
     */
    if (virStorageSourceGetActualType(src) == VIR_STORAGE_TYPE_BLOCK &&
        format != VIR_STORAGE_FILE_RAW &&
        S_ISBLK(sb.st_mode))
        src->allocation = 0;

    ret = 0;
 cleanup:
    VIR_FREE(buf);
    virStorageSourceFree(meta);
    VIR_FORCE_CLOSE(fd);
    virStorageFileDeinit(src);
    return ret;
}


static int
qemuDomainGetBlockInfo(virDomainPtr dom,
                       const char *path,
                       virDomainBlockInfoPtr info,
                       unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainDiskDefPtr disk;
    virQEMUDriverConfigPtr cfg = NULL;
    int rc;
    virHashTablePtr stats = NULL;
    qemuBlockStats *entry;
    char *alias = NULL;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainGetBlockInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!(disk = virDomainDiskByName(vm->def, path, false))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path %s not assigned to domain"), path);
        goto endjob;
    }

    if (virStorageSourceIsEmpty(disk->src)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("disk '%s' does not currently have a source assigned"),
                       path);
        goto endjob;
    }

    /* for inactive domains we have to peek into the files */
    if (!virDomainObjIsActive(vm)) {
        if ((qemuStorageLimitsRefresh(driver, cfg, vm, disk->src)) < 0)
            goto endjob;

        info->capacity = disk->src->capacity;
        info->allocation = disk->src->allocation;
        info->physical = disk->src->physical;

        ret = 0;
        goto endjob;
    }

    if (!disk->info.alias ||
        !(alias = qemuDomainStorageAlias(disk->info.alias, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing disk device alias name for %s"), disk->dst);
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    rc = qemuMonitorGetAllBlockStatsInfo(qemuDomainGetMonitor(vm),
                                         &stats, false);
    if (rc >= 0)
        rc = qemuMonitorBlockStatsUpdateCapacity(qemuDomainGetMonitor(vm),
                                                 stats, false);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto endjob;

    if (!(entry = virHashLookup(stats, alias))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to gather stats for disk '%s'"), disk->dst);
        goto endjob;
    }

    if (!entry->wr_highest_offset_valid) {
        if (virStorageSourceGetActualType(disk->src) == VIR_STORAGE_TYPE_BLOCK &&
            disk->src->format != VIR_STORAGE_FILE_RAW) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to query the maximum written offset of "
                             "block device '%s'"), disk->dst);
            goto endjob;
        }

        info->allocation = entry->physical;
    } else {
        info->allocation = entry->wr_highest_offset;
    }

    if (entry->physical) {
        info->physical = entry->physical;
    } else {
        if (virStorageSourceUpdateBlockPhysicalSize(disk->src, true) < 0)
            goto endjob;

        info->physical = disk->src->physical;
    }

    info->capacity = entry->capacity;

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);
 cleanup:
    VIR_FREE(alias);
    virHashFree(stats);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


static int
qemuConnectDomainEventRegister(virConnectPtr conn,
                               virConnectDomainEventCallback callback,
                               void *opaque,
                               virFreeCallback freecb)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        goto cleanup;

    if (virDomainEventStateRegister(conn,
                                    driver->domainEventState,
                                    callback, opaque, freecb) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int
qemuConnectDomainEventDeregister(virConnectPtr conn,
                                 virConnectDomainEventCallback callback)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        goto cleanup;

    if (virDomainEventStateDeregister(conn,
                                      driver->domainEventState,
                                      callback) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int
qemuConnectDomainEventRegisterAny(virConnectPtr conn,
                                  virDomainPtr dom,
                                  int eventID,
                                  virConnectDomainEventGenericCallback callback,
                                  void *opaque,
                                  virFreeCallback freecb)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virDomainEventStateRegisterID(conn,
                                      driver->domainEventState,
                                      dom, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;

 cleanup:
    return ret;
}


static int
qemuConnectDomainEventDeregisterAny(virConnectPtr conn,
                                    int callbackID)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->domainEventState,
                                        callbackID) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


/*******************************************************************
 * Migration Protocol Version 2
 *******************************************************************/

/* Prepare is the first step, and it runs on the destination host.
 *
 * This version starts an empty VM listening on a localhost TCP port, and
 * sets up the corresponding virStream to handle the incoming data.
 */
static int
qemuDomainMigratePrepareTunnel(virConnectPtr dconn,
                               virStreamPtr st,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource ATTRIBUTE_UNUSED,
                               const char *dom_xml)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    char *origname = NULL;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (!(flags & VIR_MIGRATE_TUNNELLED)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("PrepareTunnel called but no TUNNELLED flag set"));
        goto cleanup;
    }

    if (virLockManagerPluginUsesState(driver->lockManager)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot use migrate v2 protocol with lock manager %s"),
                       virLockManagerPluginGetName(driver->lockManager));
        goto cleanup;
    }

    if (!(def = qemuMigrationPrepareDef(driver, dom_xml, dname, &origname)))
        goto cleanup;

    if (virDomainMigratePrepareTunnelEnsureACL(dconn, def) < 0)
        goto cleanup;

    ret = qemuMigrationPrepareTunnel(driver, dconn,
                                     NULL, 0, NULL, NULL, /* No cookies in v2 */
                                     st, &def, origname, flags);

 cleanup:
    VIR_FREE(origname);
    virDomainDefFree(def);
    return ret;
}

/* Prepare is the first step, and it runs on the destination host.
 *
 * This starts an empty VM listening on a TCP port.
 */
static int ATTRIBUTE_NONNULL(5)
qemuDomainMigratePrepare2(virConnectPtr dconn,
                          char **cookie ATTRIBUTE_UNUSED,
                          int *cookielen ATTRIBUTE_UNUSED,
                          const char *uri_in,
                          char **uri_out,
                          unsigned long flags,
                          const char *dname,
                          unsigned long resource ATTRIBUTE_UNUSED,
                          const char *dom_xml)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    char *origname = NULL;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (flags & VIR_MIGRATE_TUNNELLED) {
        /* this is a logical error; we never should have gotten here with
         * VIR_MIGRATE_TUNNELLED set
         */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Tunnelled migration requested but invalid "
                         "RPC method called"));
        goto cleanup;
    }

    if (virLockManagerPluginUsesState(driver->lockManager)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot use migrate v2 protocol with lock manager %s"),
                       virLockManagerPluginGetName(driver->lockManager));
        goto cleanup;
    }

    if (!(def = qemuMigrationPrepareDef(driver, dom_xml, dname, &origname)))
        goto cleanup;

    if (virDomainMigratePrepare2EnsureACL(dconn, def) < 0)
        goto cleanup;

    /* Do not use cookies in v2 protocol, since the cookie
     * length was not sufficiently large, causing failures
     * migrating between old & new libvirtd
     */
    ret = qemuMigrationPrepareDirect(driver, dconn,
                                     NULL, 0, NULL, NULL, /* No cookies */
                                     uri_in, uri_out,
                                     &def, origname, NULL, 0, NULL, flags);

 cleanup:
    VIR_FREE(origname);
    virDomainDefFree(def);
    return ret;
}


/* Perform is the second step, and it runs on the source host. */
static int
qemuDomainMigratePerform(virDomainPtr dom,
                         const char *cookie,
                         int cookielen,
                         const char *uri,
                         unsigned long flags,
                         const char *dname,
                         unsigned long resource)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    const char *dconnuri = NULL;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (virLockManagerPluginUsesState(driver->lockManager)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot use migrate v2 protocol with lock manager %s"),
                       virLockManagerPluginGetName(driver->lockManager));
        goto cleanup;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMigratePerformEnsureACL(dom->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        dconnuri = uri;
        uri = NULL;
    }

    /* Do not output cookies in v2 protocol, since the cookie
     * length was not sufficiently large, causing failures
     * migrating between old & new libvirtd.
     *
     * Consume any cookie we were able to decode though
     */
    ret = qemuMigrationPerform(driver, dom->conn, vm,
                               NULL, dconnuri, uri, NULL, NULL, 0, NULL,
                               cookie, cookielen,
                               NULL, NULL, /* No output cookies in v2 */
                               flags, dname, resource, false);

 cleanup:
    return ret;
}


/* Finish is the third and final step, and it runs on the destination host. */
static virDomainPtr
qemuDomainMigrateFinish2(virConnectPtr dconn,
                         const char *dname,
                         const char *cookie ATTRIBUTE_UNUSED,
                         int cookielen ATTRIBUTE_UNUSED,
                         const char *uri ATTRIBUTE_UNUSED,
                         unsigned long flags,
                         int retcode)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);

    vm = virDomainObjListFindByName(driver->domains, dname);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), dname);
        qemuMigrationErrorReport(driver, dname);
        goto cleanup;
    }

    if (virDomainMigrateFinish2EnsureACL(dconn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        goto cleanup;
    }

    /* Do not use cookies in v2 protocol, since the cookie
     * length was not sufficiently large, causing failures
     * migrating between old & new libvirtd
     */
    dom = qemuMigrationFinish(driver, dconn, vm,
                              NULL, 0, NULL, NULL, /* No cookies */
                              flags, retcode, false);

 cleanup:
    return dom;
}


/*******************************************************************
 * Migration Protocol Version 3
 *******************************************************************/

static char *
qemuDomainMigrateBegin3(virDomainPtr domain,
                        const char *xmlin,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned long flags,
                        const char *dname,
                        unsigned long resource ATTRIBUTE_UNUSED)
{
    virDomainObjPtr vm;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return NULL;

    if (virDomainMigrateBegin3EnsureACL(domain->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return NULL;
    }

    return qemuMigrationBegin(domain->conn, vm, xmlin, dname,
                              cookieout, cookieoutlen, 0, NULL, flags);
}

static char *
qemuDomainMigrateBegin3Params(virDomainPtr domain,
                              virTypedParameterPtr params,
                              int nparams,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned int flags)
{
    const char *xmlin = NULL;
    const char *dname = NULL;
    const char **migrate_disks = NULL;
    int nmigrate_disks;
    char *ret = NULL;
    virDomainObjPtr vm;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &xmlin) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0)
        goto cleanup;

    nmigrate_disks = virTypedParamsGetStringList(params, nparams,
                                                 VIR_MIGRATE_PARAM_MIGRATE_DISKS,
                                                 &migrate_disks);

    if (nmigrate_disks < 0)
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainMigrateBegin3ParamsEnsureACL(domain->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        goto cleanup;
    }

    ret = qemuMigrationBegin(domain->conn, vm, xmlin, dname,
                             cookieout, cookieoutlen,
                             nmigrate_disks, migrate_disks, flags);

 cleanup:
    VIR_FREE(migrate_disks);
    return ret;
}


static int
qemuDomainMigratePrepare3(virConnectPtr dconn,
                          const char *cookiein,
                          int cookieinlen,
                          char **cookieout,
                          int *cookieoutlen,
                          const char *uri_in,
                          char **uri_out,
                          unsigned long flags,
                          const char *dname,
                          unsigned long resource ATTRIBUTE_UNUSED,
                          const char *dom_xml)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    char *origname = NULL;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (flags & VIR_MIGRATE_TUNNELLED) {
        /* this is a logical error; we never should have gotten here with
         * VIR_MIGRATE_TUNNELLED set
         */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Tunnelled migration requested but invalid "
                         "RPC method called"));
        goto cleanup;
    }

    if (!(def = qemuMigrationPrepareDef(driver, dom_xml, dname, &origname)))
        goto cleanup;

    if (virDomainMigratePrepare3EnsureACL(dconn, def) < 0)
        goto cleanup;

    ret = qemuMigrationPrepareDirect(driver, dconn,
                                     cookiein, cookieinlen,
                                     cookieout, cookieoutlen,
                                     uri_in, uri_out,
                                     &def, origname, NULL, 0, NULL, flags);

 cleanup:
    VIR_FREE(origname);
    virDomainDefFree(def);
    return ret;
}

static int
qemuDomainMigratePrepare3Params(virConnectPtr dconn,
                                virTypedParameterPtr params,
                                int nparams,
                                const char *cookiein,
                                int cookieinlen,
                                char **cookieout,
                                int *cookieoutlen,
                                char **uri_out,
                                unsigned int flags)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainDefPtr def = NULL;
    const char *dom_xml = NULL;
    const char *dname = NULL;
    const char *uri_in = NULL;
    const char *listenAddress = cfg->migrationAddress;
    int nmigrate_disks;
    const char **migrate_disks = NULL;
    char *origname = NULL;
    int ret = -1;

    virCheckFlagsGoto(QEMU_MIGRATION_FLAGS, cleanup);
    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri_in) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_LISTEN_ADDRESS,
                                &listenAddress) < 0)
        goto cleanup;

    nmigrate_disks = virTypedParamsGetStringList(params, nparams,
                                                 VIR_MIGRATE_PARAM_MIGRATE_DISKS,
                                                 &migrate_disks);

    if (nmigrate_disks < 0)
        goto cleanup;

    if (flags & VIR_MIGRATE_TUNNELLED) {
        /* this is a logical error; we never should have gotten here with
         * VIR_MIGRATE_TUNNELLED set
         */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Tunnelled migration requested but invalid "
                         "RPC method called"));
        goto cleanup;
    }

    if (!(def = qemuMigrationPrepareDef(driver, dom_xml, dname, &origname)))
        goto cleanup;

    if (virDomainMigratePrepare3ParamsEnsureACL(dconn, def) < 0)
        goto cleanup;

    ret = qemuMigrationPrepareDirect(driver, dconn,
                                     cookiein, cookieinlen,
                                     cookieout, cookieoutlen,
                                     uri_in, uri_out,
                                     &def, origname, listenAddress,
                                     nmigrate_disks, migrate_disks, flags);

 cleanup:
    VIR_FREE(migrate_disks);
    VIR_FREE(origname);
    virDomainDefFree(def);
    virObjectUnref(cfg);
    return ret;
}


static int
qemuDomainMigratePrepareTunnel3(virConnectPtr dconn,
                                virStreamPtr st,
                                const char *cookiein,
                                int cookieinlen,
                                char **cookieout,
                                int *cookieoutlen,
                                unsigned long flags,
                                const char *dname,
                                unsigned long resource ATTRIBUTE_UNUSED,
                                const char *dom_xml)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    char *origname = NULL;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (!(flags & VIR_MIGRATE_TUNNELLED)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("PrepareTunnel called but no TUNNELLED flag set"));
        goto cleanup;
    }

    if (!(def = qemuMigrationPrepareDef(driver, dom_xml, dname, &origname)))
        goto cleanup;

    if (virDomainMigratePrepareTunnel3EnsureACL(dconn, def) < 0)
        goto cleanup;

    ret = qemuMigrationPrepareTunnel(driver, dconn,
                                     cookiein, cookieinlen,
                                     cookieout, cookieoutlen,
                                     st, &def, origname, flags);

 cleanup:
    VIR_FREE(origname);
    virDomainDefFree(def);
    return ret;
}

static int
qemuDomainMigratePrepareTunnel3Params(virConnectPtr dconn,
                                      virStreamPtr st,
                                      virTypedParameterPtr params,
                                      int nparams,
                                      const char *cookiein,
                                      int cookieinlen,
                                      char **cookieout,
                                      int *cookieoutlen,
                                      unsigned int flags)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainDefPtr def = NULL;
    const char *dom_xml = NULL;
    const char *dname = NULL;
    char *origname = NULL;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        return -1;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0)
        return -1;

    if (!(flags & VIR_MIGRATE_TUNNELLED)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("PrepareTunnel called but no TUNNELLED flag set"));
        goto cleanup;
    }

    if (!(def = qemuMigrationPrepareDef(driver, dom_xml, dname, &origname)))
        goto cleanup;

    if (virDomainMigratePrepareTunnel3ParamsEnsureACL(dconn, def) < 0)
        goto cleanup;

    ret = qemuMigrationPrepareTunnel(driver, dconn,
                                     cookiein, cookieinlen,
                                     cookieout, cookieoutlen,
                                     st, &def, origname, flags);

 cleanup:
    VIR_FREE(origname);
    virDomainDefFree(def);
    return ret;
}


static int
qemuDomainMigratePerform3(virDomainPtr dom,
                          const char *xmlin,
                          const char *cookiein,
                          int cookieinlen,
                          char **cookieout,
                          int *cookieoutlen,
                          const char *dconnuri,
                          const char *uri,
                          unsigned long flags,
                          const char *dname,
                          unsigned long resource)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainMigratePerform3EnsureACL(dom->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return -1;
    }

    return qemuMigrationPerform(driver, dom->conn, vm, xmlin,
                                dconnuri, uri, NULL, NULL, 0, NULL,
                                cookiein, cookieinlen,
                                cookieout, cookieoutlen,
                                flags, dname, resource, true);
}

static int
qemuDomainMigratePerform3Params(virDomainPtr dom,
                                const char *dconnuri,
                                virTypedParameterPtr params,
                                int nparams,
                                const char *cookiein,
                                int cookieinlen,
                                char **cookieout,
                                int *cookieoutlen,
                                unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *dom_xml = NULL;
    const char *dname = NULL;
    const char *uri = NULL;
    const char *graphicsuri = NULL;
    const char *listenAddress = NULL;
    int nmigrate_disks;
    const char **migrate_disks = NULL;
    unsigned long long bandwidth = 0;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        return ret;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri) < 0 ||
        virTypedParamsGetULLong(params, nparams,
                                VIR_MIGRATE_PARAM_BANDWIDTH,
                                &bandwidth) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_GRAPHICS_URI,
                                &graphicsuri) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_LISTEN_ADDRESS,
                                &listenAddress) < 0)
        goto cleanup;

    nmigrate_disks = virTypedParamsGetStringList(params, nparams,
                                                 VIR_MIGRATE_PARAM_MIGRATE_DISKS,
                                                 &migrate_disks);

    if (nmigrate_disks < 0)
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMigratePerform3ParamsEnsureACL(dom->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        goto cleanup;
    }

    ret = qemuMigrationPerform(driver, dom->conn, vm, dom_xml,
                               dconnuri, uri, graphicsuri, listenAddress,
                               nmigrate_disks, migrate_disks,
                               cookiein, cookieinlen, cookieout, cookieoutlen,
                               flags, dname, bandwidth, true);
 cleanup:
    VIR_FREE(migrate_disks);
    return ret;
}


static virDomainPtr
qemuDomainMigrateFinish3(virConnectPtr dconn,
                         const char *dname,
                         const char *cookiein,
                         int cookieinlen,
                         char **cookieout,
                         int *cookieoutlen,
                         const char *dconnuri ATTRIBUTE_UNUSED,
                         const char *uri ATTRIBUTE_UNUSED,
                         unsigned long flags,
                         int cancelled)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainObjPtr vm;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);

    if (!dname) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("missing domain name"));
        return NULL;
    }

    vm = virDomainObjListFindByName(driver->domains, dname);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), dname);
        qemuMigrationErrorReport(driver, dname);
        return NULL;
    }

    if (virDomainMigrateFinish3EnsureACL(dconn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return NULL;
    }

    return qemuMigrationFinish(driver, dconn, vm,
                               cookiein, cookieinlen,
                               cookieout, cookieoutlen,
                               flags, cancelled, true);
}

static virDomainPtr
qemuDomainMigrateFinish3Params(virConnectPtr dconn,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               unsigned int flags,
                               int cancelled)
{
    virQEMUDriverPtr driver = dconn->privateData;
    virDomainObjPtr vm;
    const char *dname = NULL;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        return NULL;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0)
        return NULL;

    if (!dname) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("missing domain name"));
        return NULL;
    }

    vm = virDomainObjListFindByName(driver->domains, dname);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), dname);
        qemuMigrationErrorReport(driver, dname);
        return NULL;
    }

    if (virDomainMigrateFinish3ParamsEnsureACL(dconn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return NULL;
    }

    return qemuMigrationFinish(driver, dconn, vm,
                               cookiein, cookieinlen,
                               cookieout, cookieoutlen,
                               flags, cancelled, true);
}


static int
qemuDomainMigrateConfirm3(virDomainPtr domain,
                          const char *cookiein,
                          int cookieinlen,
                          unsigned long flags,
                          int cancelled)
{
    virDomainObjPtr vm;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    if (virDomainMigrateConfirm3EnsureACL(domain->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return -1;
    }

    return qemuMigrationConfirm(domain->conn, vm, cookiein, cookieinlen,
                                flags, cancelled);
}

static int
qemuDomainMigrateConfirm3Params(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                const char *cookiein,
                                int cookieinlen,
                                unsigned int flags,
                                int cancelled)
{
    virDomainObjPtr vm;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        return -1;

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    if (virDomainMigrateConfirm3ParamsEnsureACL(domain->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return -1;
    }

    return qemuMigrationConfirm(domain->conn, vm, cookiein, cookieinlen,
                                flags, cancelled);
}


static int
qemuNodeDeviceGetPCIInfo(virNodeDeviceDefPtr def,
                         unsigned *domain,
                         unsigned *bus,
                         unsigned *slot,
                         unsigned *function)
{
    virNodeDevCapsDefPtr cap;
    int ret = -1;

    cap = def->caps;
    while (cap) {
        if (cap->data.type == VIR_NODE_DEV_CAP_PCI_DEV) {
            *domain   = cap->data.pci_dev.domain;
            *bus      = cap->data.pci_dev.bus;
            *slot     = cap->data.pci_dev.slot;
            *function = cap->data.pci_dev.function;
            break;
        }

        cap = cap->next;
    }

    if (!cap) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("device %s is not a PCI device"), def->name);
        goto out;
    }

    ret = 0;
 out:
    return ret;
}

static int
qemuNodeDeviceDetachFlags(virNodeDevicePtr dev,
                          const char *driverName,
                          unsigned int flags)
{
    virQEMUDriverPtr driver = dev->conn->privateData;
    virPCIDevicePtr pci = NULL;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;
    virNodeDeviceDefPtr def = NULL;
    char *xml = NULL;
    bool legacy = qemuHostdevHostSupportsPassthroughLegacy();
    bool vfio = qemuHostdevHostSupportsPassthroughVFIO();
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virCheckFlags(0, -1);

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceDetachFlagsEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (qemuNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    if (!driverName) {
        if (vfio) {
            driverName = "vfio";
        } else if (legacy) {
            driverName = "kvm";
        } else {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("neither VFIO nor KVM device assignment is "
                             "currently supported on this system"));
            goto cleanup;
        }
    }

    if (STREQ(driverName, "vfio")) {
        if (!vfio) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("VFIO device assignment is currently not "
                             "supported on this system"));
            goto cleanup;
        }
        virPCIDeviceSetStubDriver(pci, VIR_PCI_STUB_DRIVER_VFIO);
    } else if (STREQ(driverName, "kvm")) {
        if (!legacy) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("KVM device assignment is currently not "
                             "supported on this system"));
            goto cleanup;
        }
        virPCIDeviceSetStubDriver(pci, VIR_PCI_STUB_DRIVER_KVM);
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown driver name '%s'"), driverName);
        goto cleanup;
    }

    ret = virHostdevPCINodeDeviceDetach(hostdev_mgr, pci);
 cleanup:
    virPCIDeviceFree(pci);
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}

static int
qemuNodeDeviceDettach(virNodeDevicePtr dev)
{
    return qemuNodeDeviceDetachFlags(dev, NULL, 0);
}

static int
qemuNodeDeviceReAttach(virNodeDevicePtr dev)
{
    virQEMUDriverPtr driver = dev->conn->privateData;
    virPCIDevicePtr pci = NULL;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;
    virNodeDeviceDefPtr def = NULL;
    char *xml = NULL;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceReAttachEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (qemuNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    ret = virHostdevPCINodeDeviceReAttach(hostdev_mgr, pci);

    virPCIDeviceFree(pci);
 cleanup:
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}

static int
qemuNodeDeviceReset(virNodeDevicePtr dev)
{
    virQEMUDriverPtr driver = dev->conn->privateData;
    virPCIDevicePtr pci;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;
    virNodeDeviceDefPtr def = NULL;
    char *xml = NULL;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceResetEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (qemuNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    ret = virHostdevPCINodeDeviceReset(hostdev_mgr, pci);

    virPCIDeviceFree(pci);
 cleanup:
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}

static int
qemuConnectCompareCPU(virConnectPtr conn,
                      const char *xmlDesc,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = VIR_CPU_COMPARE_ERROR;
    virCapsPtr caps = NULL;
    bool failIncompatible;

    virCheckFlags(VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE,
                  VIR_CPU_COMPARE_ERROR);

    if (virConnectCompareCPUEnsureACL(conn) < 0)
        goto cleanup;

    failIncompatible = !!(flags & VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!caps->host.cpu ||
        !caps->host.cpu->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("cannot get host CPU capabilities"));
        } else {
            VIR_WARN("cannot get host CPU capabilities");
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        }
    } else {
        ret = cpuCompareXML(caps->host.cpu, xmlDesc, failIncompatible);
    }

 cleanup:
    virObjectUnref(caps);
    return ret;
}


static char *
qemuConnectBaselineCPU(virConnectPtr conn ATTRIBUTE_UNUSED,
                       const char **xmlCPUs,
                       unsigned int ncpus,
                       unsigned int flags)
{
    char *cpu = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (virConnectBaselineCPUEnsureACL(conn) < 0)
        goto cleanup;

    cpu = cpuBaselineXML(xmlCPUs, ncpus, NULL, 0, flags);

 cleanup:
    return cpu;
}


static int
qemuDomainGetJobStatsInternal(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              bool completed,
                              qemuDomainJobInfoPtr jobInfo)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr info;
    bool fetch = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);
    int ret = -1;

    if (completed)
        fetch = false;

    /* Do not ask QEMU if migration is not even running yet  */
    if (!priv->job.current || !priv->job.current->status.status)
        fetch = false;

    if (fetch &&
        qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        return -1;

    if (!completed &&
        !virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto cleanup;
    }

    if (completed)
        info = priv->job.completed;
    else
        info = priv->job.current;

    if (!info) {
        jobInfo->type = VIR_DOMAIN_JOB_NONE;
        ret = 0;
        goto cleanup;
    }
    *jobInfo = *info;

    if (jobInfo->type == VIR_DOMAIN_JOB_BOUNDED ||
        jobInfo->type == VIR_DOMAIN_JOB_UNBOUNDED) {
        if (fetch)
            ret = qemuMigrationFetchJobStatus(driver, vm, QEMU_ASYNC_JOB_NONE,
                                              jobInfo);
        else
            ret = qemuDomainJobInfoUpdateTime(jobInfo);
    } else {
        ret = 0;
    }

 cleanup:
    if (fetch)
        qemuDomainObjEndJob(driver, vm);
    return ret;
}


static int
qemuDomainGetJobInfo(virDomainPtr dom,
                     virDomainJobInfoPtr info)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainJobInfo jobInfo;
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetJobInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainGetJobStatsInternal(driver, vm, false, &jobInfo) < 0)
        goto cleanup;

    if (jobInfo.type == VIR_DOMAIN_JOB_NONE) {
        memset(info, 0, sizeof(*info));
        info->type = VIR_DOMAIN_JOB_NONE;
        ret = 0;
        goto cleanup;
    }

    ret = qemuDomainJobInfoToInfo(&jobInfo, info);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainGetJobStats(virDomainPtr dom,
                      int *type,
                      virTypedParameterPtr *params,
                      int *nparams,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    qemuDomainJobInfo jobInfo;
    bool completed = !!(flags & VIR_DOMAIN_JOB_STATS_COMPLETED);
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_JOB_STATS_COMPLETED, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetJobStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;
    if (qemuDomainGetJobStatsInternal(driver, vm, completed, &jobInfo) < 0)
        goto cleanup;

    if (jobInfo.type == VIR_DOMAIN_JOB_NONE) {
        *type = VIR_DOMAIN_JOB_NONE;
        *params = NULL;
        *nparams = 0;
        ret = 0;
        goto cleanup;
    }

    ret = qemuDomainJobInfoToParams(&jobInfo, type, params, nparams);

    if (completed && ret == 0)
        VIR_FREE(priv->job.completed);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int qemuDomainAbortJob(virDomainPtr dom)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAbortJobEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_ABORT) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (!priv->job.asyncJob || priv->job.dump_memory_only) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("no job is active on the domain"));
        goto endjob;
    } else if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_IN) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot abort incoming migration;"
                         " use virDomainDestroy instead"));
        goto endjob;
    }

    VIR_DEBUG("Cancelling job at client request");
    qemuDomainObjAbortAsyncJob(vm);
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorMigrateCancel(priv->mon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainMigrateSetMaxDowntime(virDomainPtr dom,
                                unsigned long long downtime,
                                unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMigrateSetMaxDowntimeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MIGRATION_OP) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    VIR_DEBUG("Setting migration downtime to %llums", downtime);
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSetMigrationDowntime(priv->mon, downtime);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainMigrateGetCompressionCache(virDomainPtr dom,
                                     unsigned long long *cacheSize,
                                     unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMigrateGetCompressionCacheEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    qemuDomainObjEnterMonitor(driver, vm);

    ret = qemuMonitorGetMigrationCapability(
                priv->mon,
                QEMU_MONITOR_MIGRATION_CAPS_XBZRLE);
    if (ret == 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Compressed migration is not supported by "
                         "QEMU binary"));
        ret = -1;
    } else if (ret > 0) {
        ret = qemuMonitorGetMigrationCacheSize(priv->mon, cacheSize);
    }

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainMigrateSetCompressionCache(virDomainPtr dom,
                                     unsigned long long cacheSize,
                                     unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMigrateSetCompressionCacheEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MIGRATION_OP) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    qemuDomainObjEnterMonitor(driver, vm);

    ret = qemuMonitorGetMigrationCapability(
                priv->mon,
                QEMU_MONITOR_MIGRATION_CAPS_XBZRLE);
    if (ret == 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Compressed migration is not supported by "
                         "QEMU binary"));
        ret = -1;
    } else if (ret > 0) {
        VIR_DEBUG("Setting compression cache to %llu B", cacheSize);
        ret = qemuMonitorSetMigrationCacheSize(priv->mon, cacheSize);
    }

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainMigrateSetMaxSpeed(virDomainPtr dom,
                             unsigned long bandwidth,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainMigrateSetMaxSpeedEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (bandwidth > QEMU_DOMAIN_MIG_BANDWIDTH_MAX) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("bandwidth must be less than %llu"),
                       QEMU_DOMAIN_MIG_BANDWIDTH_MAX + 1ULL);
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MIGRATION_OP) < 0)
            goto cleanup;

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is not running"));
            goto endjob;
        }

        VIR_DEBUG("Setting migration bandwidth to %luMbs", bandwidth);
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSetMigrationSpeed(priv->mon, bandwidth);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;

        if (ret == 0)
            priv->migMaxBandwidth = bandwidth;

 endjob:
        qemuDomainObjEndJob(driver, vm);
    } else {
        priv->migMaxBandwidth = bandwidth;
        ret = 0;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainMigrateGetMaxSpeed(virDomainPtr dom,
                             unsigned long *bandwidth,
                             unsigned int flags)
{
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainMigrateGetMaxSpeedEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *bandwidth = priv->migMaxBandwidth;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


typedef enum {
    VIR_DISK_CHAIN_NO_ACCESS,
    VIR_DISK_CHAIN_READ_ONLY,
    VIR_DISK_CHAIN_READ_WRITE,
} qemuDomainDiskChainMode;

/* Several operations end up adding or removing a single element of a disk
 * backing file chain; this helper function ensures that the lock manager,
 * cgroup device controller, and security manager labelling are all aware of
 * each new file before it is added to a chain, and can revoke access to a file
 * no longer needed in a chain.  */
static int
qemuDomainPrepareDiskChainElement(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virStorageSourcePtr elem,
                                  qemuDomainDiskChainMode mode)
{
    bool readonly = elem->readonly;
    virQEMUDriverConfigPtr cfg = NULL;
    int ret = -1;

    cfg = virQEMUDriverGetConfig(driver);

    elem->readonly = mode == VIR_DISK_CHAIN_READ_ONLY;

    if (mode == VIR_DISK_CHAIN_NO_ACCESS) {
        if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                                vm->def, elem) < 0)
            VIR_WARN("Unable to restore security label on %s", elem->path);

        if (qemuSetImageCgroup(vm, elem, true) < 0)
            VIR_WARN("Failed to teardown cgroup for disk path %s", elem->path);

        if (virDomainLockImageDetach(driver->lockManager, vm, elem) < 0)
            VIR_WARN("Unable to release lock on %s", elem->path);
    } else {
        if (virDomainLockImageAttach(driver->lockManager, cfg->uri,
                                     vm, elem) < 0)
            goto cleanup;

        if (qemuSetImageCgroup(vm, elem, false) < 0)
            goto cleanup;

        if (virSecurityManagerSetImageLabel(driver->securityManager,
                                            vm->def, elem) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    elem->readonly = readonly;
    virObjectUnref(cfg);
    return ret;
}


/* Return -1 if request is not sent to agent due to misconfig, -2 if request
 * is sent but failed, and number of frozen filesystems on success. If -2 is
 * returned, FSThaw should be called revert the quiesced status. */
static int
qemuDomainSnapshotFSFreeze(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                           virDomainObjPtr vm,
                           const char **mountpoints,
                           unsigned int nmountpoints)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int frozen;

    if (!qemuDomainAgentAvailable(vm, true))
        return -1;

    qemuDomainObjEnterAgent(vm);
    frozen = qemuAgentFSFreeze(priv->agent, mountpoints, nmountpoints);
    qemuDomainObjExitAgent(vm);
    return frozen < 0 ? -2 : frozen;
}


/* Return -1 on error, otherwise number of thawed filesystems. */
static int
qemuDomainSnapshotFSThaw(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                         virDomainObjPtr vm,
                         bool report)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int thawed;
    virErrorPtr err = NULL;

    if (!qemuDomainAgentAvailable(vm, report))
        return -1;

    qemuDomainObjEnterAgent(vm);
    if (!report)
        err = virSaveLastError();
    thawed = qemuAgentFSThaw(priv->agent);
    if (!report)
        virSetError(err);
    qemuDomainObjExitAgent(vm);

    virFreeError(err);

    return thawed;
}


/* The domain is expected to be locked and inactive. */
static int
qemuDomainSnapshotCreateInactiveInternal(virQEMUDriverPtr driver,
                                         virDomainObjPtr vm,
                                         virDomainSnapshotObjPtr snap)
{
    return qemuDomainSnapshotForEachQcow2(driver, vm, snap, "-c", false);
}


/* The domain is expected to be locked and inactive. */
static int
qemuDomainSnapshotCreateInactiveExternal(virQEMUDriverPtr driver,
                                         virDomainObjPtr vm,
                                         virDomainSnapshotObjPtr snap,
                                         bool reuse)
{
    size_t i;
    virDomainSnapshotDiskDefPtr snapdisk;
    virDomainDiskDefPtr defdisk;
    virCommandPtr cmd = NULL;
    const char *qemuImgPath;
    virBitmapPtr created = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;

    if (!(qemuImgPath = qemuFindQemuImgBinary(driver)))
        goto cleanup;

    if (!(created = virBitmapNew(snap->def->ndisks)))
        goto cleanup;

    /* If reuse is true, then qemuDomainSnapshotPrepare already
     * ensured that the new files exist, and it was up to the user to
     * create them correctly.  */
    for (i = 0; i < snap->def->ndisks && !reuse; i++) {
        snapdisk = &(snap->def->disks[i]);
        defdisk = snap->def->dom->disks[snapdisk->idx];
        if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (!snapdisk->src->format)
            snapdisk->src->format = VIR_STORAGE_FILE_QCOW2;

        /* creates cmd line args: qemu-img create -f qcow2 -o */
        if (!(cmd = virCommandNewArgList(qemuImgPath,
                                         "create",
                                         "-f",
                                         virStorageFileFormatTypeToString(snapdisk->src->format),
                                         "-o",
                                         NULL)))
            goto cleanup;

        if (defdisk->src->format > 0) {
            /* adds cmd line arg: backing_file=/path/to/backing/file,backing_fmd=format */
            virCommandAddArgFormat(cmd, "backing_file=%s,backing_fmt=%s",
                                   defdisk->src->path,
                                   virStorageFileFormatTypeToString(defdisk->src->format));
        } else {
            if (!cfg->allowDiskFormatProbing) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown image format of '%s' and "
                                 "format probing is disabled"),
                               defdisk->src->path);
                goto cleanup;
            }

            /* adds cmd line arg: backing_file=/path/to/backing/file */
            virCommandAddArgFormat(cmd, "backing_file=%s", defdisk->src->path);
        }

        /* adds cmd line args: /path/to/target/file */
        virCommandAddArg(cmd, snapdisk->src->path);

        /* If the target does not exist, we're going to create it possibly */
        if (!virFileExists(snapdisk->src->path))
            ignore_value(virBitmapSetBit(created, i));

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = NULL;
    }

    /* update disk definitions */
    for (i = 0; i < snap->def->ndisks; i++) {
        snapdisk = &(snap->def->disks[i]);
        defdisk = vm->def->disks[snapdisk->idx];

        if (snapdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            VIR_FREE(defdisk->src->path);
            if (VIR_STRDUP(defdisk->src->path, snapdisk->src->path) < 0) {
                /* we cannot rollback here in a sane way */
                goto cleanup;
            }
            defdisk->src->format = snapdisk->src->format;

            if (virDomainSaveConfig(cfg->configDir, vm->def) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virCommandFree(cmd);

    /* unlink images if creation has failed */
    if (ret < 0 && created) {
        ssize_t bit = -1;
        while ((bit = virBitmapNextSetBit(created, bit)) >= 0) {
            snapdisk = &(snap->def->disks[bit]);
            if (unlink(snapdisk->src->path) < 0)
                VIR_WARN("Failed to remove snapshot image '%s'",
                         snapdisk->src->path);
        }
    }
    virBitmapFree(created);
    virObjectUnref(cfg);

    return ret;
}


/* The domain is expected to be locked and active. */
static int
qemuDomainSnapshotCreateActiveInternal(virConnectPtr conn,
                                       virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainSnapshotObjPtr snap,
                                       unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virObjectEventPtr event = NULL;
    bool resume = false;
    int ret = -1;

    if (!qemuMigrationIsAllowed(driver, vm, false, 0))
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        /* savevm monitor command pauses the domain emitting an event which
         * confuses libvirt since it's not notified when qemu resumes the
         * domain. Thus we stop and start CPUs ourselves.
         */
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SAVE,
                                QEMU_ASYNC_JOB_SNAPSHOT) < 0)
            goto cleanup;

        resume = true;
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto cleanup;
        }
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_SNAPSHOT) < 0) {
        resume = false;
        goto cleanup;
    }

    ret = qemuMonitorCreateSnapshot(priv->mon, snap->def->name);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        resume = false;
    }

 cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm, conn,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_SNAPSHOT) < 0) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        if (virGetLastError() == NULL) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }
    }

    qemuDomainEventQueue(driver, event);

    return ret;
}


static int
qemuDomainSnapshotPrepareDiskExternalBackingInactive(virDomainDiskDefPtr disk)
{
    int actualType = virStorageSourceGetActualType(disk->src);

    switch ((virStorageType) actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        return 0;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) disk->src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("external inactive snapshots are not supported on "
                             "'network' disks using '%s' protocol"),
                           virStorageNetProtocolTypeToString(disk->src->protocol));
            return -1;
        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external inactive snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(actualType));
        return -1;
    }

    return 0;
}


static int
qemuDomainSnapshotPrepareDiskExternalBackingActive(virDomainDiskDefPtr disk)
{
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("external active snapshots are not supported on scsi "
                         "passthrough devices"));
        return -1;
    }

    return 0;
}


static int
qemuDomainSnapshotPrepareDiskExternalOverlayActive(virDomainSnapshotDiskDefPtr disk)
{
    int actualType = virStorageSourceGetActualType(disk->src);

    switch ((virStorageType) actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        return 0;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) disk->src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            return 0;

        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("external active snapshots are not supported on "
                             "'network' disks using '%s' protocol"),
                           virStorageNetProtocolTypeToString(disk->src->protocol));
            return -1;

        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external active snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(actualType));
        return -1;
    }

    return 0;
}


static int
qemuDomainSnapshotPrepareDiskExternalOverlayInactive(virDomainSnapshotDiskDefPtr disk)
{
    int actualType = virStorageSourceGetActualType(disk->src);

    switch ((virStorageType) actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        return 0;

    case VIR_STORAGE_TYPE_NETWORK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("external inactive snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(actualType));
        return -1;
    }

    return 0;
}


static int
qemuDomainSnapshotPrepareDiskExternal(virConnectPtr conn,
                                      virDomainDiskDefPtr disk,
                                      virDomainSnapshotDiskDefPtr snapdisk,
                                      bool active,
                                      bool reuse)
{
    int ret = -1;
    struct stat st;

    if (qemuTranslateSnapshotDiskSourcePool(conn, snapdisk) < 0)
        return -1;

    if (!active) {
        if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
            return -1;

        if (qemuDomainSnapshotPrepareDiskExternalBackingInactive(disk) < 0)
            return -1;

        if (qemuDomainSnapshotPrepareDiskExternalOverlayInactive(snapdisk) < 0)
            return -1;
    } else {
        if (qemuDomainSnapshotPrepareDiskExternalBackingActive(disk) < 0)
            return -1;

        if (qemuDomainSnapshotPrepareDiskExternalOverlayActive(snapdisk) < 0)
            return -1;
    }

    if (virStorageFileInit(snapdisk->src) < 0)
        return -1;

    if (virStorageFileStat(snapdisk->src, &st) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("unable to stat for disk %s: %s"),
                                 snapdisk->name, snapdisk->src->path);
            goto cleanup;
        } else if (reuse) {
            virReportSystemError(errno,
                                 _("missing existing file for disk %s: %s"),
                                 snapdisk->name, snapdisk->src->path);
            goto cleanup;
        }
    } else if (!S_ISBLK(st.st_mode) && st.st_size && !reuse) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("external snapshot file for disk %s already "
                         "exists and is not a block device: %s"),
                       snapdisk->name, snapdisk->src->path);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStorageFileDeinit(snapdisk->src);
    return ret;
}


static int
qemuDomainSnapshotPrepareDiskInternal(virConnectPtr conn,
                                      virDomainDiskDefPtr disk,
                                      bool active)
{
    int actualType;

    /* active disks are handled by qemu itself so no need to worry about those */
    if (active)
        return 0;

    if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
        return -1;

    actualType = virStorageSourceGetActualType(disk->src);

    switch ((virStorageType) actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        return 0;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) disk->src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("internal inactive snapshots are not supported on "
                             "'network' disks using '%s' protocol"),
                           virStorageNetProtocolTypeToString(disk->src->protocol));
            return -1;
        }
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("internal inactive snapshots are not supported on "
                         "'%s' disks"), virStorageTypeToString(actualType));
        return -1;
    }

    return 0;
}


static int
qemuDomainSnapshotPrepare(virConnectPtr conn,
                          virDomainObjPtr vm,
                          virDomainSnapshotDefPtr def,
                          unsigned int *flags)
{
    int ret = -1;
    size_t i;
    bool active = virDomainObjIsActive(vm);
    bool reuse = (*flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    bool atomic = (*flags & VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC) != 0;
    bool found_internal = false;
    bool forbid_internal = false;
    int external = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (def->state == VIR_DOMAIN_DISK_SNAPSHOT &&
        reuse && !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_TRANSACTION)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("reuse is not supported with this QEMU binary"));
        goto cleanup;
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainSnapshotDiskDefPtr disk = &def->disks[i];
        virDomainDiskDefPtr dom_disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr dom_diskPriv = QEMU_DOMAIN_DISK_PRIVATE(dom_disk);

        if (disk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_NONE &&
            dom_diskPriv->blockjob) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' has an active block job"),
                           disk->name);
            goto cleanup;
        }

        switch ((virDomainSnapshotLocation) disk->snapshot) {
        case VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL:
            found_internal = true;

            if (def->state == VIR_DOMAIN_DISK_SNAPSHOT && active) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("active qemu domains require external disk "
                                 "snapshots; disk %s requested internal"),
                               disk->name);
                goto cleanup;
            }

            if (qemuDomainSnapshotPrepareDiskInternal(conn, dom_disk,
                                                      active) < 0)
                goto cleanup;

            if (vm->def->disks[i]->src->format > 0 &&
                vm->def->disks[i]->src->format != VIR_STORAGE_FILE_QCOW2) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("internal snapshot for disk %s unsupported "
                                 "for storage type %s"),
                               disk->name,
                               virStorageFileFormatTypeToString(
                                   vm->def->disks[i]->src->format));
                goto cleanup;
            }
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL:
            if (!disk->src->format) {
                disk->src->format = VIR_STORAGE_FILE_QCOW2;
            } else if (disk->src->format != VIR_STORAGE_FILE_QCOW2 &&
                       disk->src->format != VIR_STORAGE_FILE_QED) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("external snapshot format for disk %s "
                                 "is unsupported: %s"),
                               disk->name,
                               virStorageFileFormatTypeToString(disk->src->format));
                goto cleanup;
            }

            if (qemuDomainSnapshotPrepareDiskExternal(conn, dom_disk, disk,
                                                      active, reuse) < 0)
                goto cleanup;

            external++;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_NONE:
            /* Remember seeing a disk that has snapshot disabled */
            if (!dom_disk->src->readonly)
                forbid_internal = true;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT:
        case VIR_DOMAIN_SNAPSHOT_LOCATION_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected code path"));
            goto cleanup;
        }
    }

    if (!found_internal && !external &&
        def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("nothing selected for snapshot"));
        goto cleanup;
    }

    /* internal snapshot requires a disk image to store the memory image to, and
     * also disks can't be excluded from an internal snapshot*/
    if ((def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL && !found_internal) ||
        (found_internal && forbid_internal)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("internal snapshots and checkpoints require all "
                         "disks to be selected for snapshot"));
        goto cleanup;
    }

    /* disk snapshot requires at least one disk */
    if (def->state == VIR_DOMAIN_DISK_SNAPSHOT && !external) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("disk-only snapshots require at least "
                         "one disk to be selected for snapshot"));
        goto cleanup;
    }

    /* For now, we don't allow mixing internal and external disks.
     * XXX technically, we could mix internal and external disks for
     * offline snapshots */
    if ((found_internal && external) ||
         (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL && external) ||
         (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL && found_internal)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("mixing internal and external targets for a snapshot "
                         "is not yet supported"));
        goto cleanup;
    }

    /* Alter flags to let later users know what we learned.  */
    if (external && !active)
        *flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;

    if (def->state != VIR_DOMAIN_DISK_SNAPSHOT && active) {
        if (external == 1 ||
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_TRANSACTION)) {
            *flags |= VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC;
        } else if (atomic && external > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("atomic live snapshot of multiple disks "
                             "is unsupported"));
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    return ret;
}


/* The domain is expected to hold monitor lock.  */
static int
qemuDomainSnapshotCreateSingleDiskActive(virQEMUDriverPtr driver,
                                         virDomainObjPtr vm,
                                         virDomainSnapshotDiskDefPtr snap,
                                         virDomainDiskDefPtr disk,
                                         virDomainDiskDefPtr persistDisk,
                                         virJSONValuePtr actions,
                                         bool reuse,
                                         qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virStorageSourcePtr newDiskSrc = NULL;
    virStorageSourcePtr persistDiskSrc = NULL;
    char *device = NULL;
    char *source = NULL;
    const char *formatStr = NULL;
    int ret = -1, rc;
    bool need_unlink = false;

    if (snap->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected code path"));
        return -1;
    }

    if (virAsprintf(&device, "drive-%s", disk->info.alias) < 0)
        goto cleanup;

    if (!(newDiskSrc = virStorageSourceCopy(snap->src, false)))
        goto cleanup;

    if (virStorageSourceInitChainElement(newDiskSrc, disk->src, false) < 0)
        goto cleanup;

    if (qemuDomainStorageFileInit(driver, vm, newDiskSrc) < 0)
        goto cleanup;

    if (qemuGetDriveSourceString(newDiskSrc, NULL, &source) < 0)
        goto cleanup;

    if (persistDisk) {
        if (!(persistDiskSrc = virStorageSourceCopy(snap->src, false)))
            goto cleanup;

        if (virStorageSourceInitChainElement(persistDiskSrc, persistDisk->src,
                                             false) < 0)
            goto cleanup;
    }

    /* pre-create the image file so that we can label it before handing it to qemu */
    if (!reuse && newDiskSrc->type != VIR_STORAGE_TYPE_BLOCK) {
        if (virStorageFileCreate(newDiskSrc) < 0) {
            virReportSystemError(errno, _("failed to create image file '%s'"),
                                 source);
            goto cleanup;
        }
        need_unlink = true;
    }

    /* set correct security, cgroup and locking options on the new image */
    if (qemuDomainPrepareDiskChainElement(driver, vm, newDiskSrc,
                                          VIR_DISK_CHAIN_READ_WRITE) < 0) {
        qemuDomainPrepareDiskChainElement(driver, vm, newDiskSrc,
                                          VIR_DISK_CHAIN_NO_ACCESS);
        goto cleanup;
    }

    /* create the actual snapshot */
    if (newDiskSrc->format)
        formatStr = virStorageFileFormatTypeToString(newDiskSrc->format);

    /* The monitor is only accessed if qemu doesn't support transactions.
     * Otherwise the following monitor command only constructs the command.
     */
    if (!actions &&
        qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    ret = rc = qemuMonitorDiskSnapshot(priv->mon, actions, device, source,
                                       formatStr, reuse);
    if (!actions) {
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;
    }

    virDomainAuditDisk(vm, disk->src, snap->src, "snapshot", rc >= 0);
    if (ret < 0)
        goto cleanup;

    /* Update vm in place to match changes.  */
    need_unlink = false;

    newDiskSrc->backingStore = disk->src;
    disk->src = newDiskSrc;
    newDiskSrc = NULL;

    if (persistDisk) {
        persistDiskSrc->backingStore = persistDisk->src;
        persistDisk->src = persistDiskSrc;
        persistDiskSrc = NULL;
    }

 cleanup:
    if (need_unlink && virStorageFileUnlink(newDiskSrc))
        VIR_WARN("unable to unlink just-created %s", source);
    virStorageFileDeinit(newDiskSrc);
    virStorageSourceFree(newDiskSrc);
    virStorageSourceFree(persistDiskSrc);
    VIR_FREE(device);
    VIR_FREE(source);
    return ret;
}


/* The domain is expected to hold monitor lock.  This is the
 * counterpart to qemuDomainSnapshotCreateSingleDiskActive, called
 * only on a failed transaction. */
static void
qemuDomainSnapshotUndoSingleDiskActive(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainDiskDefPtr disk,
                                       virDomainDiskDefPtr persistDisk,
                                       bool need_unlink)
{
    virStorageSourcePtr tmp;
    struct stat st;

    ignore_value(virStorageFileInit(disk->src));

    qemuDomainPrepareDiskChainElement(driver, vm, disk->src,
                                      VIR_DISK_CHAIN_NO_ACCESS);
    if (need_unlink &&
        virStorageFileStat(disk->src, &st) == 0 && S_ISREG(st.st_mode) &&
        virStorageFileUnlink(disk->src) < 0)
        VIR_WARN("Unable to remove just-created %s", disk->src->path);

    virStorageFileDeinit(disk->src);

    /* Update vm in place to match changes. */
    tmp = disk->src;
    disk->src = tmp->backingStore;
    tmp->backingStore = NULL;
    virStorageSourceFree(tmp);

    if (persistDisk) {
        tmp = persistDisk->src;
        persistDisk->src = tmp->backingStore;
        tmp->backingStore = NULL;
        virStorageSourceFree(tmp);
    }
}


/* The domain is expected to be locked and active. */
static int
qemuDomainSnapshotCreateDiskActive(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainSnapshotObjPtr snap,
                                   unsigned int flags,
                                   qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virJSONValuePtr actions = NULL;
    int ret = 0;
    size_t i;
    bool persist = false;
    bool reuse = (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    virQEMUDriverConfigPtr cfg = NULL;
    virErrorPtr orig_err = NULL;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        return -1;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_TRANSACTION)) {
        if (!(actions = virJSONValueNewArray()))
            return -1;
    } else if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DISK_SNAPSHOT)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("live disk snapshot not supported with this "
                         "QEMU binary"));
        return -1;
    }

    cfg = virQEMUDriverGetConfig(driver);

    /* No way to roll back if first disk succeeds but later disks
     * fail, unless we have transaction support.
     * Based on earlier qemuDomainSnapshotPrepare, all
     * disks in this list are now either SNAPSHOT_NO, or
     * SNAPSHOT_EXTERNAL with a valid file name and qcow2 format.  */
    for (i = 0; i < snap->def->ndisks; i++) {
        virDomainDiskDefPtr persistDisk = NULL;

        if (snap->def->disks[i].snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)
            continue;
        if (vm->newDef &&
            (persistDisk = virDomainDiskByName(vm->newDef,
                                               vm->def->disks[i]->dst,
                                               false)))
            persist = true;

        ret = qemuDomainSnapshotCreateSingleDiskActive(driver, vm,
                                                       &snap->def->disks[i],
                                                       vm->def->disks[i],
                                                       persistDisk, actions,
                                                       reuse, asyncJob);
        if (ret < 0)
            break;
    }
    if (actions) {
        if (ret == 0) {
            if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
                ret = qemuMonitorTransaction(priv->mon, actions);
                if (qemuDomainObjExitMonitor(driver, vm) < 0)
                    ret = -1;
            } else {
                /* failed to enter monitor, clean stuff up and quit */
                ret = -1;
            }
        }

        virJSONValueFree(actions);

        if (ret < 0) {
            /* Transaction failed; undo the changes to vm.  */
            bool need_unlink = !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT);
            while (i-- > 0) {
                virDomainDiskDefPtr persistDisk = NULL;

                if (snap->def->disks[i].snapshot ==
                    VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)
                    continue;
                if (vm->newDef &&
                    (persistDisk = virDomainDiskByName(vm->newDef,
                                                       vm->def->disks[i]->dst,
                                                       false)))
                    persist = true;

                qemuDomainSnapshotUndoSingleDiskActive(driver, vm,
                                                       vm->def->disks[i],
                                                       persistDisk,
                                                       need_unlink);
            }
        }
    }

    /* recheck backing chains of all disks involved in the snapshot */
    orig_err = virSaveLastError();
    for (i = 0; i < snap->def->ndisks; i++) {
        if (snap->def->disks[i].snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;
        ignore_value(qemuDomainDetermineDiskChain(driver, vm, vm->def->disks[i],
                                                  true, true));
    }
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

    if (ret == 0 || !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_TRANSACTION)) {
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0 ||
            (persist && virDomainSaveConfig(cfg->configDir, vm->newDef) < 0))
            ret = -1;
    }
    virObjectUnref(cfg);

    return ret;
}


static int
qemuDomainSnapshotCreateActiveExternal(virConnectPtr conn,
                                       virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainSnapshotObjPtr snap,
                                       unsigned int flags)
{
    virObjectEventPtr event;
    bool resume = false;
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *xml = NULL;
    bool memory = snap->def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
    bool memory_unlink = false;
    bool atomic = !!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC);
    bool transaction = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_TRANSACTION);
    int thaw = 0; /* 1 if freeze succeeded, -1 if freeze failed */
    bool pmsuspended = false;
    virQEMUDriverConfigPtr cfg = NULL;
    int compressed = QEMU_SAVE_FORMAT_RAW;

    /* If quiesce was requested, then issue a freeze command, and a
     * counterpart thaw command when it is actually sent to agent.
     * The command will fail if the guest is paused or the guest agent
     * is not running, or is already quiesced.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE) {
        int freeze = qemuDomainSnapshotFSFreeze(driver, vm, NULL, 0);
        if (freeze < 0) {
            /* the helper reported the error */
            if (freeze == -2)
                thaw = -1; /* the command is sent but agent failed */
            goto cleanup;
        }
        thaw = 1;
    }

    /* We need to track what state the guest is in, since taking the
     * snapshot may alter that state and we must restore it later.  */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PMSUSPENDED) {
        pmsuspended = true;
    } else if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        resume = true;

        /* For external checkpoints (those with memory), the guest
         * must pause (either by libvirt up front, or by qemu after
         * _LIVE converges).  For disk-only snapshots with multiple
         * disks, libvirt must pause externally to get all snapshots
         * to be at the same point in time, unless qemu supports
         * transactions.  For a single disk, snapshot is atomic
         * without requiring a pause.  Thanks to
         * qemuDomainSnapshotPrepare, if we got to this point, the
         * atomic flag now says whether we need to pause, and a
         * capability bit says whether to use transaction.
         */
        if ((memory && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_LIVE)) ||
            (!memory && atomic && !transaction)) {
            if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SNAPSHOT,
                                    QEMU_ASYNC_JOB_SNAPSHOT) < 0)
                goto cleanup;

            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("guest unexpectedly quit"));
                goto cleanup;
            }
        }
    }

    /* do the memory snapshot if necessary */
    if (memory) {
        /* check if migration is possible */
        if (!qemuMigrationIsAllowed(driver, vm, false, 0))
            goto cleanup;

        /* allow the migration job to be cancelled or the domain to be paused */
        qemuDomainObjSetAsyncJobMask(vm, (QEMU_JOB_DEFAULT_MASK |
                                          JOB_MASK(QEMU_JOB_SUSPEND) |
                                          JOB_MASK(QEMU_JOB_MIGRATION_OP)));

        cfg = virQEMUDriverGetConfig(driver);
        if (cfg->snapshotImageFormat) {
            compressed = qemuSaveCompressionTypeFromString(cfg->snapshotImageFormat);
            if (compressed < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Invalid snapshot image format specified "
                                 "in configuration file"));
                goto cleanup;
            }

            if (!qemuCompressProgramAvailable(compressed)) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Compression program for image format "
                                 "in configuration file isn't available"));
                goto cleanup;
            }
        }

        if (!(xml = qemuDomainDefFormatLive(driver, vm->def, true, true)))
            goto cleanup;

        if ((ret = qemuDomainSaveMemory(driver, vm, snap->def->file,
                                        xml, compressed, resume, 0,
                                        QEMU_ASYNC_JOB_SNAPSHOT)) < 0)
            goto cleanup;

        /* the memory image was created, remove it on errors */
        memory_unlink = true;

        /* forbid any further manipulation */
        qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_DEFAULT_MASK);
    }

    /* now the domain is now paused if:
     * - if a memory snapshot was requested
     * - an atomic snapshot was requested AND
     *   qemu does not support transactions
     *
     * Next we snapshot the disks.
     */
    if ((ret = qemuDomainSnapshotCreateDiskActive(driver, vm, snap, flags,
                                                  QEMU_ASYNC_JOB_SNAPSHOT)) < 0)
        goto cleanup;

    /* the snapshot is complete now */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        resume = false;
        thaw = 0;
        qemuDomainEventQueue(driver, event);
    } else if (memory && pmsuspended) {
        /* qemu 1.3 is unable to save a domain in pm-suspended (S3)
         * state; so we must emit an event stating that it was
         * converted to paused.  */
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT);
        qemuDomainEventQueue(driver, event);
    }

    ret = 0;

 cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm, conn,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_SNAPSHOT) < 0) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        qemuDomainEventQueue(driver, event);
        if (virGetLastError() == NULL) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }

        ret = -1;
        goto cleanup;
    }

    if (thaw != 0 &&
        qemuDomainSnapshotFSThaw(driver, vm, thaw > 0) < 0) {
        /* helper reported the error, if it was needed */
        if (thaw > 0)
            ret = -1;
    }

    VIR_FREE(xml);
    virObjectUnref(cfg);
    if (memory_unlink && ret < 0)
        unlink(snap->def->file);

    return ret;
}


static virDomainSnapshotPtr
qemuDomainSnapshotCreateXML(virDomainPtr domain,
                            const char *xmlDesc,
                            unsigned int flags)
{
    virConnectPtr conn = domain->conn;
    virQEMUDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    char *xml = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    virDomainSnapshotDefPtr def = NULL;
    bool update_current = true;
    bool redefine = flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    unsigned int parse_flags = VIR_DOMAIN_SNAPSHOT_PARSE_DISKS;
    virDomainSnapshotObjPtr other = NULL;
    int align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
    bool align_match = true;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT |
                  VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA |
                  VIR_DOMAIN_SNAPSHOT_CREATE_HALT |
                  VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY |
                  VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT |
                  VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC |
                  VIR_DOMAIN_SNAPSHOT_CREATE_LIVE, NULL);

    VIR_REQUIRE_FLAG_RET(VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE,
                         VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY,
                         NULL);

    if ((redefine && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) ||
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA))
        update_current = false;
    if (redefine)
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSnapshotCreateXMLEnsureACL(domain->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuProcessAutoDestroyActive(driver, vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is marked for auto destroy"));
        goto cleanup;
    }

    if (!vm->persistent && (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot halt after transient domain snapshot"));
        goto cleanup;
    }
    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) ||
        !virDomainObjIsActive(vm))
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE;

    if (!(def = virDomainSnapshotDefParseString(xmlDesc, caps, driver->xmlopt,
                                                parse_flags)))
        goto cleanup;

    /* reject snapshot names containing slashes or starting with dot as
     * snapshot definitions are saved in files named by the snapshot name */
    if (!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA)) {
        if (strchr(def->name, '/')) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid snapshot name '%s': "
                             "name can't contain '/'"),
                           def->name);
            goto cleanup;
        }

        if (def->name[0] == '.') {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid snapshot name '%s': "
                             "name can't start with '.'"),
                           def->name);
            goto cleanup;
        }
    }

    /* reject the VIR_DOMAIN_SNAPSHOT_CREATE_LIVE flag where not supported */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_LIVE &&
        (!virDomainObjIsActive(vm) ||
         def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL ||
         redefine)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("live snapshot creation is supported only "
                         "with external checkpoints"));
        goto cleanup;
    }

    /* allow snapshots only in certain states */
    switch ((virDomainState) vm->state.state) {
        /* valid states */
    case VIR_DOMAIN_RUNNING:
    case VIR_DOMAIN_PAUSED:
    case VIR_DOMAIN_SHUTDOWN:
    case VIR_DOMAIN_SHUTOFF:
    case VIR_DOMAIN_CRASHED:
        break;

    case VIR_DOMAIN_PMSUSPENDED:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu doesn't support taking snapshots of "
                         "PMSUSPENDED guests"));
        goto cleanup;

        /* invalid states */
    case VIR_DOMAIN_NOSTATE:
    case VIR_DOMAIN_BLOCKED: /* invalid state, unused in qemu */
    case VIR_DOMAIN_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid domain state %s"),
                       virDomainStateTypeToString(vm->state.state));
        goto cleanup;
    }

    /* We are going to modify the domain below. Internal snapshots would use
     * a regular job, so we need to set the job mask to disallow query as
     * 'savevm' blocks the monitor. External snapshot will then modify the
     * job mask appropriately. */
    if (qemuDomainObjBeginAsyncJob(driver, vm, QEMU_ASYNC_JOB_SNAPSHOT) < 0)
        goto cleanup;

    qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_NONE);

    if (redefine) {
        if (virDomainSnapshotRedefinePrep(domain, vm, &def, &snap,
                                          &update_current, flags) < 0)
            goto endjob;
    } else {
        /* Easiest way to clone inactive portion of vm->def is via
         * conversion in and back out of xml.  */
        if (!(xml = qemuDomainDefFormatLive(driver, vm->def, true, true)) ||
            !(def->dom = virDomainDefParseString(xml, caps, driver->xmlopt,
                                                 VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto endjob;

        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
            align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
            align_match = false;
            if (virDomainObjIsActive(vm))
                def->state = VIR_DOMAIN_DISK_SNAPSHOT;
            else
                def->state = VIR_DOMAIN_SHUTOFF;
            def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
        } else if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            def->state = virDomainObjGetState(vm, NULL);
            align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
            align_match = false;
        } else {
            def->state = virDomainObjGetState(vm, NULL);

            if (virDomainObjIsActive(vm) &&
                def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("internal snapshot of a running VM "
                                 "must include the memory state"));
                goto endjob;
            }

            def->memory = (def->state == VIR_DOMAIN_SHUTOFF ?
                           VIR_DOMAIN_SNAPSHOT_LOCATION_NONE :
                           VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL);
        }
        if (virDomainSnapshotAlignDisks(def, align_location,
                                        align_match) < 0 ||
            qemuDomainSnapshotPrepare(conn, vm, def, &flags) < 0)
            goto endjob;
    }

    if (!snap) {
        if (!(snap = virDomainSnapshotAssignDef(vm->snapshots, def)))
            goto endjob;

        def = NULL;
    }

    if (update_current)
        snap->def->current = true;
    if (vm->current_snapshot) {
        if (!redefine &&
            VIR_STRDUP(snap->def->parent, vm->current_snapshot->def->name) < 0)
                goto endjob;
        if (update_current) {
            vm->current_snapshot->def->current = false;
            if (qemuDomainSnapshotWriteMetadata(vm, vm->current_snapshot,
                                                cfg->snapshotDir) < 0)
                goto endjob;
            vm->current_snapshot = NULL;
        }
    }

    /* actually do the snapshot */
    if (redefine) {
        /* XXX Should we validate that the redefined snapshot even
         * makes sense, such as checking that qemu-img recognizes the
         * snapshot name in at least one of the domain's disks?  */
    } else if (virDomainObjIsActive(vm)) {
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY ||
            snap->def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            /* external checkpoint or disk snapshot */
            if (qemuDomainSnapshotCreateActiveExternal(domain->conn, driver,
                                                       vm, snap, flags) < 0)
                goto endjob;
        } else {
            /* internal checkpoint */
            if (qemuDomainSnapshotCreateActiveInternal(domain->conn, driver,
                                                       vm, snap, flags) < 0)
                goto endjob;
        }
    } else {
        /* inactive; qemuDomainSnapshotPrepare guaranteed that we
         * aren't mixing internal and external, and altered flags to
         * contain DISK_ONLY if there is an external disk.  */
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
            bool reuse = !!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT);

            if (qemuDomainSnapshotCreateInactiveExternal(driver, vm, snap,
                                                         reuse) < 0)
                goto endjob;
        } else {
            if (qemuDomainSnapshotCreateInactiveInternal(driver, vm, snap) < 0)
                goto endjob;
        }
    }

    /* If we fail after this point, there's not a whole lot we can
     * do; we've successfully taken the snapshot, and we are now running
     * on it, so we have to go forward the best we can
     */
    snapshot = virGetDomainSnapshot(domain, snap->def->name);

 endjob:
    if (snapshot && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA)) {
        if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                            cfg->snapshotDir) < 0) {
            /* if writing of metadata fails, error out rather than trying
             * to silently carry on without completing the snapshot */
            virObjectUnref(snapshot);
            snapshot = NULL;
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to save metadata for snapshot %s"),
                           snap->def->name);
            virDomainSnapshotObjListRemove(vm->snapshots, snap);
        } else {
            if (update_current)
                vm->current_snapshot = snap;
            other = virDomainSnapshotFindByName(vm->snapshots,
                                                snap->def->parent);
            snap->parent = other;
            other->nchildren++;
            snap->sibling = other->first_child;
            other->first_child = snap;
        }
    } else if (snap) {
        virDomainSnapshotObjListRemove(vm->snapshots, snap);
    }

    qemuDomainObjEndAsyncJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virDomainSnapshotDefFree(def);
    VIR_FREE(xml);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return snapshot;
}


static int
qemuDomainSnapshotListNames(virDomainPtr domain,
                            char **names,
                            int nameslen,
                            unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    if (virDomainSnapshotListNamesEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    n = virDomainSnapshotObjListGetNames(vm->snapshots, NULL, names, nameslen,
                                         flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}


static int
qemuDomainSnapshotNum(virDomainPtr domain,
                      unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    if (virDomainSnapshotNumEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    n = virDomainSnapshotObjListNum(vm->snapshots, NULL, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}


static int
qemuDomainListAllSnapshots(virDomainPtr domain,
                           virDomainSnapshotPtr **snaps,
                           unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    if (virDomainListAllSnapshotsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    n = virDomainListSnapshots(vm->snapshots, NULL, domain, snaps, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}


static int
qemuDomainSnapshotListChildrenNames(virDomainSnapshotPtr snapshot,
                                    char **names,
                                    int nameslen,
                                    unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    if (virDomainSnapshotListChildrenNamesEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainSnapshotObjListGetNames(vm->snapshots, snap, names, nameslen,
                                         flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}


static int
qemuDomainSnapshotNumChildren(virDomainSnapshotPtr snapshot,
                              unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    if (virDomainSnapshotNumChildrenEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainSnapshotObjListNum(vm->snapshots, snap, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}


static int
qemuDomainSnapshotListAllChildren(virDomainSnapshotPtr snapshot,
                                  virDomainSnapshotPtr **snaps,
                                  unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    if (virDomainSnapshotListAllChildrenEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainListSnapshots(vm->snapshots, snap, snapshot->domain, snaps,
                               flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}


static virDomainSnapshotPtr
qemuDomainSnapshotLookupByName(virDomainPtr domain,
                               const char *name,
                               unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return NULL;

    if (virDomainSnapshotLookupByNameEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromName(vm, name)))
        goto cleanup;

    snapshot = virGetDomainSnapshot(domain, snap->def->name);

 cleanup:
    virDomainObjEndAPI(&vm);
    return snapshot;
}


static int
qemuDomainHasCurrentSnapshot(virDomainPtr domain,
                             unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    if (virDomainHasCurrentSnapshotEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    ret = (vm->current_snapshot != NULL);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static virDomainSnapshotPtr
qemuDomainSnapshotGetParent(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr parent = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return NULL;

    if (virDomainSnapshotGetParentEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    if (!snap->def->parent) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("snapshot '%s' does not have a parent"),
                       snap->def->name);
        goto cleanup;
    }

    parent = virGetDomainSnapshot(snapshot->domain, snap->def->parent);

 cleanup:
    virDomainObjEndAPI(&vm);
    return parent;
}


static virDomainSnapshotPtr
qemuDomainSnapshotCurrent(virDomainPtr domain,
                          unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return NULL;

    if (virDomainSnapshotCurrentEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->current_snapshot) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT, "%s",
                       _("the domain does not have a current snapshot"));
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, vm->current_snapshot->def->name);

 cleanup:
    virDomainObjEndAPI(&vm);
    return snapshot;
}


static char *
qemuDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                             unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    char *xml = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virCheckFlags(VIR_DOMAIN_XML_SECURE, NULL);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return NULL;

    if (virDomainSnapshotGetXMLDescEnsureACL(snapshot->domain->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    virUUIDFormat(snapshot->domain->uuid, uuidstr);

    xml = virDomainSnapshotDefFormat(uuidstr, snap->def,
                                     virDomainDefFormatConvertXMLFlags(flags),
                                     0);

 cleanup:
    virDomainObjEndAPI(&vm);
    return xml;
}


static int
qemuDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainSnapshotObjPtr snap = NULL;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    if (virDomainSnapshotIsCurrentEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    ret = (vm->current_snapshot &&
           STREQ(snapshot->name, vm->current_snapshot->def->name));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot,
                              unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainSnapshotObjPtr snap = NULL;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    if (virDomainSnapshotHasMetadataEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    /* XXX Someday, we should recognize internal snapshots in qcow2
     * images that are not tied to a libvirt snapshot; if we ever do
     * that, then we would have a reason to return 0 here.  */
    ret = 1;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


/* The domain is expected to be locked and inactive. */
static int
qemuDomainSnapshotRevertInactive(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainSnapshotObjPtr snap)
{
    /* Try all disks, but report failure if we skipped any.  */
    int ret = qemuDomainSnapshotForEachQcow2(driver, vm, snap, "-a", true);
    return ret > 0 ? -1 : ret;
}


static int
qemuDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                           unsigned int flags)
{
    virQEMUDriverPtr driver = snapshot->domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainSnapshotObjPtr snap = NULL;
    virObjectEventPtr event = NULL;
    virObjectEventPtr event2 = NULL;
    int detail;
    qemuDomainObjPrivatePtr priv;
    int rc;
    virDomainDefPtr config = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    bool was_running = false;
    bool was_stopped = false;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED |
                  VIR_DOMAIN_SNAPSHOT_REVERT_FORCE, -1);

    /* We have the following transitions, which create the following events:
     * 1. inactive -> inactive: none
     * 2. inactive -> running:  EVENT_STARTED
     * 3. inactive -> paused:   EVENT_STARTED, EVENT_PAUSED
     * 4. running  -> inactive: EVENT_STOPPED
     * 5. running  -> running:  none
     * 6. running  -> paused:   EVENT_PAUSED
     * 7. paused   -> inactive: EVENT_STOPPED
     * 8. paused   -> running:  EVENT_RESUMED
     * 9. paused   -> paused:   none
     * Also, several transitions occur even if we fail partway through,
     * and use of FORCE can cause multiple transitions.
     */

    virNWFilterReadLockFilterUpdates();

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainRevertToSnapshotEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuDomainHasBlockjob(vm, false)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain has active block job"));
        goto cleanup;
    }

    if (qemuProcessBeginJob(driver, vm) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto endjob;

    if (!vm->persistent &&
        snap->def->state != VIR_DOMAIN_RUNNING &&
        snap->def->state != VIR_DOMAIN_PAUSED &&
        (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("transient domain needs to request run or pause "
                         "to revert to inactive snapshot"));
        goto endjob;
    }

    if (virDomainSnapshotIsExternal(snap)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("revert to external snapshot not supported yet"));
        goto endjob;
    }

    if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
        if (!snap->def->dom) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY,
                           _("snapshot '%s' lacks domain '%s' rollback info"),
                           snap->def->name, vm->def->name);
            goto endjob;
        }
        if (virDomainObjIsActive(vm) &&
            !(snap->def->state == VIR_DOMAIN_RUNNING
              || snap->def->state == VIR_DOMAIN_PAUSED) &&
            (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                      VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                           _("must respawn qemu to start inactive snapshot"));
            goto endjob;
        }
    }


    if (vm->current_snapshot) {
        vm->current_snapshot->def->current = false;
        if (qemuDomainSnapshotWriteMetadata(vm, vm->current_snapshot,
                                            cfg->snapshotDir) < 0)
            goto endjob;
        vm->current_snapshot = NULL;
        /* XXX Should we restore vm->current_snapshot after this point
         * in the failure cases where we know there was no change?  */
    }

    /* Prepare to copy the snapshot inactive xml as the config of this
     * domain.
     *
     * XXX Should domain snapshots track live xml rather
     * than inactive xml?  */
    snap->def->current = true;
    if (snap->def->dom) {
        config = virDomainDefCopy(snap->def->dom, caps, driver->xmlopt, true);
        if (!config)
            goto endjob;
    }

    switch ((virDomainState) snap->def->state) {
    case VIR_DOMAIN_RUNNING:
    case VIR_DOMAIN_PAUSED:
        /* Transitions 2, 3, 5, 6, 8, 9 */
        /* When using the loadvm monitor command, qemu does not know
         * whether to pause or run the reverted domain, and just stays
         * in the same state as before the monitor command, whether
         * that is paused or running.  We always pause before loadvm,
         * to have finer control.  */
        if (virDomainObjIsActive(vm)) {
            /* Transitions 5, 6, 8, 9 */
            /* Check for ABI compatibility. We need to do this check against
             * the migratable XML or it will always fail otherwise */
            if (config && !qemuDomainDefCheckABIStability(driver, vm->def, config)) {
                virErrorPtr err = virGetLastError();

                if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
                    /* Re-spawn error using correct category. */
                    if (err->code == VIR_ERR_CONFIG_UNSUPPORTED)
                        virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                                       err->str2);
                    goto endjob;
                }
                virResetError(err);
                qemuProcessStop(driver, vm,
                                VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT, 0);
                virDomainAuditStop(vm, "from-snapshot");
                detail = VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT;
                event = virDomainEventLifecycleNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_STOPPED,
                                                 detail);
                qemuDomainEventQueue(driver, event);
                goto load;
            }

            priv = vm->privateData;
            if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
                /* Transitions 5, 6 */
                was_running = true;
                if (qemuProcessStopCPUs(driver, vm,
                                        VIR_DOMAIN_PAUSED_FROM_SNAPSHOT,
                                        QEMU_ASYNC_JOB_START) < 0)
                    goto endjob;
                /* Create an event now in case the restore fails, so
                 * that user will be alerted that they are now paused.
                 * If restore later succeeds, we might replace this. */
                detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
                event = virDomainEventLifecycleNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_SUSPENDED,
                                                 detail);
                if (!virDomainObjIsActive(vm)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("guest unexpectedly quit"));
                    goto endjob;
                }
            }

            if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                               QEMU_ASYNC_JOB_START) < 0)
                goto endjob;
            rc = qemuMonitorLoadSnapshot(priv->mon, snap->def->name);
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto endjob;
            if (rc < 0) {
                /* XXX resume domain if it was running before the
                 * failed loadvm attempt? */
                goto endjob;
            }
            if (config)
                virDomainObjAssignDef(vm, config, false, NULL);
        } else {
            /* Transitions 2, 3 */
        load:
            was_stopped = true;
            if (config)
                virDomainObjAssignDef(vm, config, false, NULL);

            rc = qemuProcessStart(snapshot->domain->conn, driver, vm,
                                  QEMU_ASYNC_JOB_START, NULL, -1, NULL, snap,
                                  VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                  VIR_QEMU_PROCESS_START_PAUSED);
            virDomainAuditStart(vm, "from-snapshot", rc >= 0);
            detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STARTED,
                                             detail);
            if (rc < 0)
                goto endjob;
        }

        /* Touch up domain state.  */
        if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING) &&
            (snap->def->state == VIR_DOMAIN_PAUSED ||
             (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
            /* Transitions 3, 6, 9 */
            virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                 VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
            if (was_stopped) {
                /* Transition 3, use event as-is and add event2 */
                detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
                event2 = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  detail);
            } /* else transition 6 and 9 use event as-is */
        } else {
            /* Transitions 2, 5, 8 */
            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("guest unexpectedly quit"));
                goto endjob;
            }
            rc = qemuProcessStartCPUs(driver, vm, snapshot->domain->conn,
                                      VIR_DOMAIN_RUNNING_FROM_SNAPSHOT,
                                      QEMU_ASYNC_JOB_START);
            if (rc < 0)
                goto endjob;
            virObjectUnref(event);
            event = NULL;
            if (was_stopped) {
                /* Transition 2 */
                detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
                event = virDomainEventLifecycleNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_STARTED,
                                                 detail);
            } else if (!was_running) {
                /* Transition 8 */
                detail = VIR_DOMAIN_EVENT_RESUMED;
                event = virDomainEventLifecycleNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_RESUMED,
                                                 detail);
            }
        }
        break;

    case VIR_DOMAIN_SHUTDOWN:
    case VIR_DOMAIN_SHUTOFF:
    case VIR_DOMAIN_CRASHED:
        /* Transitions 1, 4, 7 */
        /* Newer qemu -loadvm refuses to revert to the state of a snapshot
         * created by qemu-img snapshot -c.  If the domain is running, we
         * must take it offline; then do the revert using qemu-img.
         */

        if (virDomainObjIsActive(vm)) {
            /* Transitions 4, 7 */
            qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT, 0);
            virDomainAuditStop(vm, "from-snapshot");
            detail = VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT;
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             detail);
        }

        if (qemuDomainSnapshotRevertInactive(driver, vm, snap) < 0) {
            qemuProcessEndJob(driver, vm);
            qemuDomainRemoveInactive(driver, vm);
            goto cleanup;
        }
        if (config)
            virDomainObjAssignDef(vm, config, false, NULL);

        if (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                     VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) {
            /* Flush first event, now do transition 2 or 3 */
            bool paused = (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED) != 0;
            unsigned int start_flags = 0;

            start_flags |= paused ? VIR_QEMU_PROCESS_START_PAUSED : 0;

            qemuDomainEventQueue(driver, event);
            rc = qemuProcessStart(snapshot->domain->conn, driver, vm,
                                  QEMU_ASYNC_JOB_START, NULL, -1, NULL, NULL,
                                  VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                  start_flags);
            virDomainAuditStart(vm, "from-snapshot", rc >= 0);
            if (rc < 0) {
                qemuProcessEndJob(driver, vm);
                qemuDomainRemoveInactive(driver, vm);
                goto cleanup;
            }
            detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STARTED,
                                             detail);
            if (paused) {
                detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
                event2 = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  detail);
            }
        }
        break;

    case VIR_DOMAIN_PMSUSPENDED:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu doesn't support reversion of snapshot taken in "
                         "PMSUSPENDED state"));
        goto endjob;

    case VIR_DOMAIN_NOSTATE:
    case VIR_DOMAIN_BLOCKED:
    case VIR_DOMAIN_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid target domain state '%s'. Refusing "
                         "snapshot reversion"),
                       virDomainStateTypeToString(snap->def->state));
        goto endjob;
    }

    ret = 0;

 endjob:
    qemuProcessEndJob(driver, vm);

 cleanup:
    if (ret == 0) {
        if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                            cfg->snapshotDir) < 0)
            ret = -1;
        else
            vm->current_snapshot = snap;
    } else if (snap) {
        snap->def->current = false;
    }
    if (event) {
        qemuDomainEventQueue(driver, event);
        qemuDomainEventQueue(driver, event2);
    }
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    virNWFilterUnlockFilterUpdates();

    return ret;
}


typedef struct _virQEMUSnapReparent virQEMUSnapReparent;
typedef virQEMUSnapReparent *virQEMUSnapReparentPtr;
struct _virQEMUSnapReparent {
    virQEMUDriverConfigPtr cfg;
    virDomainSnapshotObjPtr parent;
    virDomainObjPtr vm;
    int err;
    virDomainSnapshotObjPtr last;
};


static void
qemuDomainSnapshotReparentChildren(void *payload,
                                   const void *name ATTRIBUTE_UNUSED,
                                   void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    virQEMUSnapReparentPtr rep = data;

    if (rep->err < 0)
        return;

    VIR_FREE(snap->def->parent);
    snap->parent = rep->parent;

    if (rep->parent->def &&
        VIR_STRDUP(snap->def->parent, rep->parent->def->name) < 0) {
        rep->err = -1;
        return;
    }

    if (!snap->sibling)
        rep->last = snap;

    rep->err = qemuDomainSnapshotWriteMetadata(rep->vm, snap,
                                               rep->cfg->snapshotDir);
}


static int
qemuDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                         unsigned int flags)
{
    virQEMUDriverPtr driver = snapshot->domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainSnapshotObjPtr snap = NULL;
    virQEMUSnapRemove rem;
    virQEMUSnapReparent rep;
    bool metadata_only = !!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY);
    int external = 0;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY |
                  VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY, -1);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSnapshotDeleteEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto endjob;

    if (!metadata_only) {
        if (!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) &&
            virDomainSnapshotIsExternal(snap))
            external++;
        if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                     VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY))
            virDomainSnapshotForEachDescendant(snap,
                                               qemuDomainSnapshotCountExternal,
                                               &external);
        if (external) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("deletion of %d external disk snapshots not "
                             "supported yet"), external);
            goto endjob;
        }
    }

    if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                 VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)) {
        rem.driver = driver;
        rem.vm = vm;
        rem.metadata_only = metadata_only;
        rem.err = 0;
        rem.current = false;
        virDomainSnapshotForEachDescendant(snap,
                                           qemuDomainSnapshotDiscardAll,
                                           &rem);
        if (rem.err < 0)
            goto endjob;
        if (rem.current) {
            if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) {
                snap->def->current = true;
                if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                                    cfg->snapshotDir) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("failed to set snapshot '%s' as current"),
                                   snap->def->name);
                    snap->def->current = false;
                    goto endjob;
                }
            }
            vm->current_snapshot = snap;
        }
    } else if (snap->nchildren) {
        rep.cfg = cfg;
        rep.parent = snap->parent;
        rep.vm = vm;
        rep.err = 0;
        rep.last = NULL;
        virDomainSnapshotForEachChild(snap,
                                      qemuDomainSnapshotReparentChildren,
                                      &rep);
        if (rep.err < 0)
            goto endjob;
        /* Can't modify siblings during ForEachChild, so do it now.  */
        snap->parent->nchildren += snap->nchildren;
        rep.last->sibling = snap->parent->first_child;
        snap->parent->first_child = snap->first_child;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) {
        snap->nchildren = 0;
        snap->first_child = NULL;
        ret = 0;
    } else {
        virDomainSnapshotDropParent(snap);
        ret = qemuDomainSnapshotDiscard(driver, vm, snap, true, metadata_only);
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int qemuDomainQemuMonitorCommand(virDomainPtr domain, const char *cmd,
                                        char **result, unsigned int flags)
{
    virQEMUDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    bool hmp;

    virCheckFlags(VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainQemuMonitorCommandEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    qemuDomainObjTaint(driver, vm, VIR_DOMAIN_TAINT_CUSTOM_MONITOR, NULL);

    hmp = !!(flags & VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP);

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorArbitraryCommand(priv->mon, cmd, result, hmp);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static virDomainPtr qemuDomainQemuAttach(virConnectPtr conn,
                                         unsigned int pid_value,
                                         unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainPtr dom = NULL;
    virDomainChrSourceDefPtr monConfig = NULL;
    bool monJSON = false;
    pid_t pid = pid_value;
    char *pidfile = NULL;
    virQEMUCapsPtr qemuCaps = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(0, NULL);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = qemuParseCommandLinePid(caps, driver->xmlopt, pid,
                                        &pidfile, &monConfig, &monJSON)))
        goto cleanup;

    if (virDomainQemuAttachEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!monConfig) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("No monitor connection for pid %u"), pid_value);
        goto cleanup;
    }
    if (monConfig->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot connect to monitor connection of type '%s' "
                         "for pid %u"),
                       virDomainChrTypeToString(monConfig->type),
                       pid_value);
        goto cleanup;
    }

    if (!(def->name) &&
        virAsprintf(&def->name, "attach-pid-%u", pid_value) < 0)
        goto cleanup;

    if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, def->emulator)))
        goto cleanup;

    if (qemuCanonicalizeMachine(def, qemuCaps) < 0)
        goto cleanup;

    if (qemuAssignDeviceAliases(def, qemuCaps) < 0)
        goto cleanup;

    if (qemuDomainAssignAddresses(def, qemuCaps, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    virObjectRef(vm);
    def = NULL;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0) {
        qemuDomainRemoveInactive(driver, vm);
        goto cleanup;
    }

    if (qemuProcessAttach(conn, driver, vm, pid,
                          pidfile, monConfig, monJSON) < 0) {
        monConfig = NULL;
        qemuDomainObjEndJob(driver, vm);
        qemuDomainRemoveInactive(driver, vm);
        goto cleanup;
    }

    monConfig = NULL;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(def);
    virDomainChrSourceDefFree(monConfig);
    virDomainObjEndAPI(&vm);
    VIR_FREE(pidfile);
    virObjectUnref(caps);
    virObjectUnref(qemuCaps);
    return dom;
}


static int
qemuDomainOpenConsole(virDomainPtr dom,
                      const char *dev_name,
                      virStreamPtr st,
                      unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    size_t i;
    virDomainChrDefPtr chr = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_CONSOLE_SAFE |
                  VIR_DOMAIN_CONSOLE_FORCE, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (dev_name) {
        for (i = 0; !chr && i < vm->def->nconsoles; i++) {
            if (vm->def->consoles[i]->info.alias &&
                STREQ(dev_name, vm->def->consoles[i]->info.alias))
                chr = vm->def->consoles[i];
        }
        for (i = 0; !chr && i < vm->def->nserials; i++) {
            if (STREQ(dev_name, vm->def->serials[i]->info.alias))
                chr = vm->def->serials[i];
        }
        for (i = 0; !chr && i < vm->def->nparallels; i++) {
            if (STREQ(dev_name, vm->def->parallels[i]->info.alias))
                chr = vm->def->parallels[i];
        }
    } else {
        if (vm->def->nconsoles)
            chr = vm->def->consoles[0];
        else if (vm->def->nserials)
            chr = vm->def->serials[0];
    }

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find character device %s"),
                       NULLSTR(dev_name));
        goto cleanup;
    }

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %s is not using a PTY"),
                       dev_name ? dev_name : NULLSTR(chr->info.alias));
        goto cleanup;
    }

    /* handle mutually exclusive access to console devices */
    ret = virChrdevOpen(priv->devs,
                        &chr->source,
                        st,
                        (flags & VIR_DOMAIN_CONSOLE_FORCE) != 0);

    if (ret == 1) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Active console session exists for this domain"));
        ret = -1;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainOpenChannel(virDomainPtr dom,
                      const char *name,
                      virStreamPtr st,
                      unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    size_t i;
    virDomainChrDefPtr chr = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_CHANNEL_FORCE, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenChannelEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (name) {
        for (i = 0; !chr && i < vm->def->nchannels; i++) {
            if (STREQ(name, vm->def->channels[i]->info.alias))
                chr = vm->def->channels[i];

            if (vm->def->channels[i]->targetType == \
                VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
                STREQ_NULLABLE(name, vm->def->channels[i]->target.name))
                chr = vm->def->channels[i];
        }
    } else {
        if (vm->def->nchannels)
            chr = vm->def->channels[0];
    }

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find channel %s"),
                       NULLSTR(name));
        goto cleanup;
    }

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_UNIX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("channel %s is not using a UNIX socket"),
                       name ? name : NULLSTR(chr->info.alias));
        goto cleanup;
    }

    /* handle mutually exclusive access to channel devices */
    ret = virChrdevOpen(priv->devs,
                        &chr->source,
                        st,
                        (flags & VIR_DOMAIN_CHANNEL_FORCE) != 0);

    if (ret == 1) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Active channel stream exists for this domain"));
        ret = -1;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
qemuDiskPathToAlias(virDomainObjPtr vm, const char *path, int *idxret)
{
    int idx;
    char *ret = NULL;
    virDomainDiskDefPtr disk;

    idx = virDomainDiskIndexByName(vm->def, path, true);
    if (idx < 0)
        goto cleanup;

    disk = vm->def->disks[idx];
    if (idxret)
        *idxret = idx;

    if (virDomainDiskGetSource(disk)) {
        if (virAsprintf(&ret, "drive-%s", disk->info.alias) < 0)
            return NULL;
    }

 cleanup:
    if (!ret) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("No device found for specified path"));
    }
    return ret;
}

/* Called while holding the VM job lock, to implement a block job
 * abort with pivot; this updates the VM definition as appropriate, on
 * either success or failure.  */
static int
qemuDomainBlockPivot(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     const char *device,
                     virDomainDiskDefPtr disk)
{
    int ret = -1, rc;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorBlockJobInfo info;
    virStorageSourcePtr oldsrc = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!disk->mirror) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("pivot of disk '%s' requires an active copy job"),
                       disk->dst);
        goto cleanup;
    }

    /* Probe the status, if needed.  */
    if (!disk->mirrorState) {
        qemuDomainObjEnterMonitor(driver, vm);
        rc = qemuMonitorGetBlockJobInfo(priv->mon, disk->info.alias, &info);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
        if (rc < 0)
            goto cleanup;
        if (rc == 1 &&
            (info.ready == 1 ||
             (info.ready == -1 &&
              info.end == info.cur &&
              (info.type == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY ||
               info.type == VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT))))
            disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
    }

    if (disk->mirrorState != VIR_DOMAIN_DISK_MIRROR_STATE_READY) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE,
                       _("disk '%s' not ready for pivot yet"),
                       disk->dst);
        goto cleanup;
    }

    /* For active commit, the mirror is part of the already labeled
     * chain.  For blockcopy, we previously labeled only the top-level
     * image; but if the user is reusing an external image that
     * includes a backing file, the pivot may result in qemu needing
     * to open the entire backing chain, so we need to label the
     * entire chain.  This action is safe even if the backing chain
     * has already been labeled; but only necessary when we know for
     * sure that there is a backing chain.  */
    if (disk->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY) {
        oldsrc = disk->src;
        disk->src = disk->mirror;

        if (qemuDomainDetermineDiskChain(driver, vm, disk, false, true) < 0)
            goto cleanup;

        if (disk->mirror->format &&
            disk->mirror->format != VIR_STORAGE_FILE_RAW &&
            (virDomainLockDiskAttach(driver->lockManager, cfg->uri, vm,
                                     disk) < 0 ||
             qemuSetupDiskCgroup(vm, disk) < 0 ||
             virSecurityManagerSetDiskLabel(driver->securityManager, vm->def,
                                            disk) < 0))
            goto cleanup;

        disk->src = oldsrc;
        oldsrc = NULL;
    }

    /* Attempt the pivot.  Record the attempt now, to prevent duplicate
     * attempts; but the actual disk change will be made when emitting
     * the event.
     * XXX On libvirtd restarts, if we missed the qemu event, we need
     * to double check what state qemu is in.
     * XXX We should be using qemu's rerror flag to make sure the job
     * remains alive until we know its final state.
     * XXX If the abort command is synchronous but the qemu event says
     * that pivot failed, we need to reflect that failure into the
     * overall return value.  */
    disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_PIVOT;
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDrivePivot(priv->mon, device);
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        ret = -1;
        goto cleanup;
    }

    if (ret < 0) {
        /* The pivot failed. The block job in QEMU remains in the synchronised
         * phase. Reset the state we changed and return the error to the user */
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
    }

 cleanup:
    if (oldsrc)
        disk->src = oldsrc;

    virObjectUnref(cfg);
    return ret;
}


/* bandwidth in MiB/s per public API. Caller must lock vm beforehand,
 * and not access it afterwards.  */
static int
qemuDomainBlockPullCommon(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          const char *path,
                          const char *base,
                          unsigned long bandwidth,
                          unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *device = NULL;
    bool modern;
    int idx;
    virDomainDiskDefPtr disk;
    virStorageSourcePtr baseSource = NULL;
    unsigned int baseIndex = 0;
    char *basePath = NULL;
    char *backingPath = NULL;
    unsigned long long speed = bandwidth;
    int ret = -1;

    if (flags & VIR_DOMAIN_BLOCK_REBASE_RELATIVE && !base) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("flag VIR_DOMAIN_BLOCK_REBASE_RELATIVE is valid only "
                         "with non-null base"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    if (qemuDomainSupportsBlockJobs(vm, &modern) < 0)
        goto endjob;

    if (!modern) {
        if (base) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("partial block pull not supported with this "
                             "QEMU binary"));
            goto endjob;
        }

        if (bandwidth) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("setting bandwidth at start of block pull not "
                             "supported with this QEMU binary"));
            goto endjob;
        }
    }

    if (!(device = qemuDiskPathToAlias(vm, path, &idx)))
        goto endjob;
    disk = vm->def->disks[idx];

    if (qemuDomainDiskBlockJobIsActive(disk))
        goto endjob;

    if (base &&
        (virStorageFileParseChainIndex(disk->dst, base, &baseIndex) < 0 ||
         !(baseSource = virStorageFileChainLookup(disk->src, disk->src,
                                                  base, baseIndex, NULL))))
        goto endjob;

    if (baseSource) {
        if (flags & VIR_DOMAIN_BLOCK_REBASE_RELATIVE) {
            if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CHANGE_BACKING_FILE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU binary doesn't support relative "
                                 "block pull/rebase"));
                goto endjob;
            }

            if (virStorageFileGetRelativeBackingPath(disk->src->backingStore,
                                                     baseSource,
                                                     &backingPath) < 0)
                goto endjob;

            if (!backingPath) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("can't keep relative backing relationship"));
                goto endjob;
            }
        }
    }

    /* Convert bandwidth MiB to bytes, if needed */
    if (!(flags & VIR_DOMAIN_BLOCK_PULL_BANDWIDTH_BYTES)) {
        if (speed > LLONG_MAX >> 20) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("bandwidth must be less than %llu"),
                           LLONG_MAX >> 20);
            goto endjob;
        }
        speed <<= 20;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    if (baseSource)
        basePath = qemuMonitorDiskNameLookup(priv->mon, device, disk->src,
                                             baseSource);
    if (!baseSource || basePath)
        ret = qemuMonitorBlockStream(priv->mon, device, basePath, backingPath,
                                     speed, modern);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (ret < 0)
        goto endjob;

    QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob = true;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(basePath);
    VIR_FREE(backingPath);
    VIR_FREE(device);
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainBlockJobAbort(virDomainPtr dom,
                        const char *path,
                        unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    char *device = NULL;
    virDomainDiskDefPtr disk = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    bool save = false;
    int idx;
    bool modern;
    bool pivot = !!(flags & VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT);
    bool async = !!(flags & VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC);
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC |
                  VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockJobAbortEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    if (qemuDomainSupportsBlockJobs(vm, &modern) < 0)
        goto endjob;

    if (!(device = qemuDiskPathToAlias(vm, path, &idx)))
        goto endjob;
    disk = vm->def->disks[idx];

    if (disk->mirrorState != VIR_DOMAIN_DISK_MIRROR_STATE_NONE &&
        disk->mirrorState != VIR_DOMAIN_DISK_MIRROR_STATE_READY) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("another job on disk '%s' is still being ended"),
                       disk->dst);
        goto endjob;
    }

    if (modern && !async)
        qemuBlockJobSyncBegin(disk);

    if (pivot) {
        if ((ret = qemuDomainBlockPivot(driver, vm, device, disk)) < 0)
            goto endjob;
    } else {
        if (disk->mirror) {
            disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_ABORT;
            save = true;
        }

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorBlockJobCancel(qemuDomainGetMonitor(vm), device, modern);
        if (qemuDomainObjExitMonitor(driver, vm) < 0) {
            ret = -1;
            goto endjob;
        }

        if (ret < 0) {
            if (disk->mirror)
                disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
            goto endjob;
        }
    }

    /* If we have made changes to XML due to a copy job, make a best
     * effort to save it now.  But we can ignore failure, since there
     * will be further changes when the event marks completion.  */
    if (save)
        ignore_value(virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm));

    /* With synchronous block cancel, we must synthesize an event, and
     * we silently ignore the ABORT_ASYNC flag.  With asynchronous
     * block cancel, the event will come from qemu and will update the
     * XML as appropriate, but without the ABORT_ASYNC flag, we must
     * block to guarantee synchronous operation.  We do the waiting
     * while still holding the VM job, to prevent newly scheduled
     * block jobs from confusing us.  */
    if (!async) {
        if (!modern) {
            /* Older qemu that lacked async reporting also lacked
             * blockcopy and active commit, so we can hardcode the
             * event to pull and let qemuBlockJobEventProcess() handle
             * the rest as usual */
            qemuBlockJobEventProcess(driver, vm, disk,
                                     VIR_DOMAIN_BLOCK_JOB_TYPE_PULL,
                                     VIR_DOMAIN_BLOCK_JOB_CANCELED);
        } else {
            qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
            qemuBlockJobUpdate(driver, vm, disk);
            while (diskPriv->blockjob) {
                if (virDomainObjWait(vm) < 0) {
                    ret = -1;
                    goto endjob;
                }
                qemuBlockJobUpdate(driver, vm, disk);
            }
        }
    }

 endjob:
    if (disk)
        qemuBlockJobSyncEnd(driver, vm, disk);
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virObjectUnref(cfg);
    VIR_FREE(device);
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainGetBlockJobInfo(virDomainPtr dom,
                          const char *path,
                          virDomainBlockJobInfoPtr info,
                          unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk;
    int ret = -1;
    qemuMonitorBlockJobInfo rawInfo;

    virCheckFlags(VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetBlockJobInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;


    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    if (qemuDomainSupportsBlockJobs(vm, NULL) < 0)
        goto endjob;

    if (!(disk = virDomainDiskByName(vm->def, path, true))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("disk %s not found in the domain"), path);
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorGetBlockJobInfo(qemuDomainGetMonitor(vm),
                                     disk->info.alias, &rawInfo);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0)
        goto endjob;

    info->cur = rawInfo.cur;
    info->end = rawInfo.end;

    info->type = rawInfo.type;
    if (info->type == VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT &&
        disk->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT)
        info->type = disk->mirrorJob;

    if (rawInfo.bandwidth &&
        !(flags & VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES))
        rawInfo.bandwidth = VIR_DIV_UP(rawInfo.bandwidth, 1024 * 1024);
    info->bandwidth = rawInfo.bandwidth;
    if (info->bandwidth != rawInfo.bandwidth) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("bandwidth %llu cannot be represented in result"),
                       rawInfo.bandwidth);
        goto endjob;
    }

    /* Snoop block copy operations, so future cancel operations can
     * avoid checking if pivot is safe.  Save the change to XML, but
     * we can ignore failure because it is only an optimization.  We
     * hold the vm lock, so modifying the in-memory representation is
     * safe, even if we are a query rather than a modify job. */
    if (ret == 1 && disk->mirror &&
        rawInfo.ready != 0 &&
        info->cur == info->end && !disk->mirrorState) {
        virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
        ignore_value(virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm));
        virObjectUnref(cfg);
    }
 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainBlockJobSetSpeed(virDomainPtr dom,
                           const char *path,
                           unsigned long bandwidth,
                           unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    int ret = -1;
    virDomainObjPtr vm;
    bool modern;
    const char *device;
    unsigned long long speed = bandwidth;

    virCheckFlags(VIR_DOMAIN_BLOCK_JOB_SPEED_BANDWIDTH_BYTES, -1);

    /* Convert bandwidth MiB to bytes, if needed */
    if (!(flags & VIR_DOMAIN_BLOCK_JOB_SPEED_BANDWIDTH_BYTES)) {
        if (speed > LLONG_MAX >> 20) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("bandwidth must be less than %llu"),
                           LLONG_MAX >> 20);
            return -1;
        }
        speed <<= 20;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockJobSetSpeedEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    if (qemuDomainSupportsBlockJobs(vm, &modern) < 0)
        goto endjob;

    if (!(device = qemuDiskPathToAlias(vm, path, NULL)))
        goto endjob;

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorBlockJobSetSpeed(qemuDomainGetMonitor(vm),
                                      device,
                                      speed,
                                      modern);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);

    return ret;
}


/* bandwidth in bytes/s.  Caller must lock vm beforehand, and not
 * access mirror afterwards.  */
static int
qemuDomainBlockCopyCommon(virDomainObjPtr vm,
                          virConnectPtr conn,
                          const char *path,
                          virStorageSourcePtr mirror,
                          unsigned long long bandwidth,
                          unsigned int granularity,
                          unsigned long long buf_size,
                          unsigned int flags,
                          bool keepParentLabel)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuDomainObjPrivatePtr priv;
    char *device = NULL;
    virDomainDiskDefPtr disk = NULL;
    int ret = -1;
    int idx;
    struct stat st;
    bool need_unlink = false;
    virQEMUDriverConfigPtr cfg = NULL;
    const char *format = NULL;
    int desttype = virStorageSourceGetActualType(mirror);

    /* Preliminaries: find the disk we are editing, sanity checks */
    virCheckFlags(VIR_DOMAIN_BLOCK_COPY_SHALLOW |
                  VIR_DOMAIN_BLOCK_COPY_REUSE_EXT, -1);

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    device = qemuDiskPathToAlias(vm, path, &idx);
    if (!device)
        goto endjob;
    disk = vm->def->disks[idx];
    if (qemuDomainDiskBlockJobIsActive(disk))
        goto endjob;

    if (!(virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_MIRROR) &&
          virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_ASYNC))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block copy is not supported with this QEMU binary"));
        goto endjob;
    }
    if (vm->persistent) {
        /* XXX if qemu ever lets us start a new domain with mirroring
         * already active, we can relax this; but for now, the risk of
         * 'managedsave' due to libvirt-guests means we can't risk
         * this on persistent domains.  */
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not transient"));
        goto endjob;
    }

    if (qemuDomainDetermineDiskChain(driver, vm, disk, false, true) < 0)
        goto endjob;

    /* clear the _SHALLOW flag if there is only one layer */
    if (!disk->src->backingStore)
        flags &= ~VIR_DOMAIN_BLOCK_COPY_SHALLOW;

    /* unless the user provides a pre-created file, shallow copy into a raw
     * file is not possible */
    if ((flags & VIR_DOMAIN_BLOCK_COPY_SHALLOW) &&
        !(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT) &&
        mirror->format == VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("shallow copy of disk '%s' into a raw file "
                         "is not possible"),
                       disk->dst);
        goto endjob;
    }

    /* Prepare the destination file.  */
    /* XXX Allow non-file mirror destinations */
    if (!virStorageSourceIsLocalStorage(mirror)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("non-file destination not supported yet"));
        goto endjob;
    }
    if (stat(mirror->path, &st) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno, _("unable to stat for disk %s: %s"),
                                 disk->dst, mirror->path);
            goto endjob;
        } else if (flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT ||
                   desttype == VIR_STORAGE_TYPE_BLOCK) {
            virReportSystemError(errno,
                                 _("missing destination file for disk %s: %s"),
                                 disk->dst, mirror->path);
            goto endjob;
        }
    } else if (!S_ISBLK(st.st_mode)) {
        if (st.st_size && !(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("external destination file for disk %s already "
                             "exists and is not a block device: %s"),
                           disk->dst, mirror->path);
            goto endjob;
        }
        if (desttype == VIR_STORAGE_TYPE_BLOCK) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("blockdev flag requested for disk %s, but file "
                             "'%s' is not a block device"),
                           disk->dst, mirror->path);
            goto endjob;
        }
    }

    if (!mirror->format) {
        if (!(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
            mirror->format = disk->src->format;
        } else {
            /* If the user passed the REUSE_EXT flag, then either they
             * can also pass the RAW flag or use XML to tell us the format.
             * So if we get here, we assume it is safe for us to probe the
             * format from the file that we will be using.  */
            mirror->format = virStorageFileProbeFormat(mirror->path, cfg->user,
                                                       cfg->group);
        }
    }

    /* pre-create the image file */
    if (!(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
        int fd = qemuOpenFile(driver, vm, mirror->path,
                              O_WRONLY | O_TRUNC | O_CREAT,
                              &need_unlink, NULL);
        if (fd < 0)
            goto endjob;
        VIR_FORCE_CLOSE(fd);
    }

    if (mirror->format > 0)
        format = virStorageFileFormatTypeToString(mirror->format);

    if (virStorageSourceInitChainElement(mirror, disk->src,
                                         keepParentLabel) < 0)
        goto endjob;

    if (qemuDomainPrepareDiskChainElement(driver, vm, mirror,
                                          VIR_DISK_CHAIN_READ_WRITE) < 0) {
        qemuDomainPrepareDiskChainElement(driver, vm, mirror,
                                          VIR_DISK_CHAIN_NO_ACCESS);
        goto endjob;
    }

    /* Actually start the mirroring */
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDriveMirror(priv->mon, device, mirror->path, format,
                                 bandwidth, granularity, buf_size, flags);
    virDomainAuditDisk(vm, NULL, mirror, "mirror", ret >= 0);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0) {
        qemuDomainPrepareDiskChainElement(driver, vm, mirror,
                                          VIR_DISK_CHAIN_NO_ACCESS);
        goto endjob;
    }

    /* Update vm in place to match changes.  */
    need_unlink = false;
    disk->mirror = mirror;
    mirror = NULL;
    disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY;
    QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob = true;

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        VIR_WARN("Unable to save status on vm %s after state change",
                 vm->def->name);

 endjob:
    if (need_unlink && unlink(mirror->path))
        VIR_WARN("unable to unlink just-created %s", mirror->path);
    virStorageSourceFree(mirror);
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(device);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainBlockRebase(virDomainPtr dom, const char *path, const char *base,
                      unsigned long bandwidth, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    unsigned long long speed = bandwidth;
    virStorageSourcePtr dest = NULL;

    virCheckFlags(VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                  VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                  VIR_DOMAIN_BLOCK_REBASE_COPY |
                  VIR_DOMAIN_BLOCK_REBASE_COPY_RAW |
                  VIR_DOMAIN_BLOCK_REBASE_RELATIVE |
                  VIR_DOMAIN_BLOCK_REBASE_COPY_DEV |
                  VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockRebaseEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    /* For normal rebase (enhanced blockpull), the common code handles
     * everything, including vm cleanup. */
    if (!(flags & VIR_DOMAIN_BLOCK_REBASE_COPY))
        return qemuDomainBlockPullCommon(driver, vm, path, base, bandwidth, flags);

    /* If we got here, we are doing a block copy rebase. */
    if (VIR_ALLOC(dest) < 0)
        goto cleanup;
    dest->type = (flags & VIR_DOMAIN_BLOCK_REBASE_COPY_DEV) ?
        VIR_STORAGE_TYPE_BLOCK : VIR_STORAGE_TYPE_FILE;
    if (VIR_STRDUP(dest->path, base) < 0)
        goto cleanup;
    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY_RAW)
        dest->format = VIR_STORAGE_FILE_RAW;

    /* Convert bandwidth MiB to bytes, if necessary */
    if (!(flags & VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES)) {
        if (speed > LLONG_MAX >> 20) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("bandwidth must be less than %llu"),
                           LLONG_MAX >> 20);
            goto cleanup;
        }
        speed <<= 20;
    }

    /* XXX: If we are doing a shallow copy but not reusing an external
     * file, we should attempt to pre-create the destination with a
     * relative backing chain instead of qemu's default of absolute */
    if (flags & VIR_DOMAIN_BLOCK_REBASE_RELATIVE) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Relative backing during copy not supported yet"));
        goto cleanup;
    }

    /* We rely on the fact that VIR_DOMAIN_BLOCK_REBASE_SHALLOW
     * and VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT map to the same values
     * as for block copy. */
    flags &= (VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
              VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT);
    ret = qemuDomainBlockCopyCommon(vm, dom->conn, path, dest,
                                    speed, 0, 0, flags, true);
    dest = NULL;

 cleanup:
    virDomainObjEndAPI(&vm);
    virStorageSourceFree(dest);
    return ret;
}


static int
qemuDomainBlockCopy(virDomainPtr dom, const char *disk, const char *destxml,
                    virTypedParameterPtr params, int nparams,
                    unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    unsigned long long bandwidth = 0;
    unsigned int granularity = 0;
    unsigned long long buf_size = 0;
    virStorageSourcePtr dest = NULL;
    size_t i;

    virCheckFlags(VIR_DOMAIN_BLOCK_COPY_SHALLOW |
                  VIR_DOMAIN_BLOCK_COPY_REUSE_EXT, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BLOCK_COPY_BANDWIDTH,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_COPY_GRANULARITY,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BLOCK_COPY_BUF_SIZE,
                               VIR_TYPED_PARAM_ULLONG,
                               NULL) < 0)
        return -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockCopyEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        /* Typed params (wisely) refused to expose unsigned long, but
         * back-compat demands that we stick with a maximum of
         * unsigned long bandwidth in MiB/s, while our value is
         * unsigned long long in bytes/s.  Hence, we have to do
         * overflow detection if this is a 32-bit server handling a
         * 64-bit client.  */
        if (STREQ(param->field, VIR_DOMAIN_BLOCK_COPY_BANDWIDTH)) {
            if (sizeof(unsigned long) < sizeof(bandwidth) &&
                param->value.ul > ULONG_MAX * (1ULL << 20)) {
                virReportError(VIR_ERR_OVERFLOW,
                               _("bandwidth must be less than %llu bytes"),
                               ULONG_MAX * (1ULL << 20));
                goto cleanup;
            }
            bandwidth = param->value.ul;
        } else if (STREQ(param->field, VIR_DOMAIN_BLOCK_COPY_GRANULARITY)) {
            if (param->value.ui != VIR_ROUND_UP_POWER_OF_TWO(param->value.ui)) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("granularity must be power of 2"));
                goto cleanup;
            }
            granularity = param->value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BLOCK_COPY_BUF_SIZE)) {
            buf_size = param->value.ul;
        }
    }

    if (!(dest = virDomainDiskDefSourceParse(destxml, vm->def, driver->xmlopt,
                                             VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    ret = qemuDomainBlockCopyCommon(vm, dom->conn, disk, dest, bandwidth,
                                    granularity, buf_size, flags, false);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainBlockPull(virDomainPtr dom, const char *path, unsigned long bandwidth,
                    unsigned int flags)
{
    virDomainObjPtr vm;
    virCheckFlags(VIR_DOMAIN_BLOCK_PULL_BANDWIDTH_BYTES, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockPullEnsureACL(dom->conn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return -1;
    }

    return qemuDomainBlockPullCommon(dom->conn->privateData,
                                     vm, path, NULL, bandwidth, flags);
}


static int
qemuDomainBlockCommit(virDomainPtr dom,
                      const char *path,
                      const char *base,
                      const char *top,
                      unsigned long bandwidth,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm = NULL;
    char *device = NULL;
    int ret = -1;
    int idx;
    virDomainDiskDefPtr disk = NULL;
    virStorageSourcePtr topSource;
    unsigned int topIndex = 0;
    virStorageSourcePtr baseSource;
    unsigned int baseIndex = 0;
    virStorageSourcePtr top_parent = NULL;
    bool clean_access = false;
    char *topPath = NULL;
    char *basePath = NULL;
    char *backingPath = NULL;
    virStorageSourcePtr mirror = NULL;
    unsigned long long speed = bandwidth;

    /* XXX Add support for COMMIT_DELETE */
    virCheckFlags(VIR_DOMAIN_BLOCK_COMMIT_SHALLOW |
                  VIR_DOMAIN_BLOCK_COMMIT_ACTIVE |
                  VIR_DOMAIN_BLOCK_COMMIT_RELATIVE |
                  VIR_DOMAIN_BLOCK_COMMIT_BANDWIDTH_BYTES, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;
    priv = vm->privateData;

    if (virDomainBlockCommitEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }
    /* Ensure that no one backports commit to RHEL 6.2, where cancel
     * behaved differently */
    if (!(virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCK_COMMIT) &&
          virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_ASYNC))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("online commit not supported with this QEMU binary"));
        goto endjob;
    }

    /* Convert bandwidth MiB to bytes, if necessary */
    if (!(flags & VIR_DOMAIN_BLOCK_COMMIT_BANDWIDTH_BYTES)) {
        if (speed > LLONG_MAX >> 20) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("bandwidth must be less than %llu"),
                           LLONG_MAX >> 20);
            goto endjob;
        }
        speed <<= 20;
    }

    device = qemuDiskPathToAlias(vm, path, &idx);
    if (!device)
        goto endjob;
    disk = vm->def->disks[idx];

    if (!disk->src->path) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk %s has no source file to be committed"),
                       disk->dst);
        goto endjob;
    }

    if (qemuDomainDiskBlockJobIsActive(disk))
        goto endjob;
    if (qemuDomainDetermineDiskChain(driver, vm, disk, false, true) < 0)
        goto endjob;

    if (!top)
        topSource = disk->src;
    else if (virStorageFileParseChainIndex(disk->dst, top, &topIndex) < 0 ||
             !(topSource = virStorageFileChainLookup(disk->src, NULL,
                                                     top, topIndex,
                                                     &top_parent)))
        goto endjob;

    if (topSource == disk->src) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_ACTIVE_COMMIT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("active commit not supported with this QEMU binary"));
            goto endjob;
        }
        /* XXX Should we auto-pivot when COMMIT_ACTIVE is not specified? */
        if (!(flags & VIR_DOMAIN_BLOCK_COMMIT_ACTIVE)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("commit of '%s' active layer requires active flag"),
                           disk->dst);
            goto endjob;
        }
    } else if (flags & VIR_DOMAIN_BLOCK_COMMIT_ACTIVE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("active commit requested but '%s' is not active"),
                       topSource->path);
        goto endjob;
    }

    if (!topSource->backingStore) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("top '%s' in chain for '%s' has no backing file"),
                       topSource->path, path);
        goto endjob;
    }

    if (!base && (flags & VIR_DOMAIN_BLOCK_COMMIT_SHALLOW))
        baseSource = topSource->backingStore;
    else if (virStorageFileParseChainIndex(disk->dst, base, &baseIndex) < 0 ||
             !(baseSource = virStorageFileChainLookup(disk->src, topSource,
                                                      base, baseIndex, NULL)))
        goto endjob;

    if ((flags & VIR_DOMAIN_BLOCK_COMMIT_SHALLOW) &&
        baseSource != topSource->backingStore) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("base '%s' is not immediately below '%s' in chain "
                         "for '%s'"),
                       base, topSource->path, path);
        goto endjob;
    }

    /* For an active commit, clone enough of the base to act as the mirror */
    if (topSource == disk->src) {
        if (!(mirror = virStorageSourceCopy(baseSource, false)))
            goto endjob;
        if (virStorageSourceInitChainElement(mirror,
                                             disk->src,
                                             true) < 0)
            goto endjob;
    }

    /* For the commit to succeed, we must allow qemu to open both the
     * 'base' image and the parent of 'top' as read/write; 'top' might
     * not have a parent, or might already be read-write.  XXX It
     * would also be nice to revert 'base' to read-only, as well as
     * revoke access to files removed from the chain, when the commit
     * operation succeeds, but doing that requires tracking the
     * operation in XML across libvirtd restarts.  */
    clean_access = true;
    if (qemuDomainPrepareDiskChainElement(driver, vm, baseSource,
                                          VIR_DISK_CHAIN_READ_WRITE) < 0 ||
        (top_parent && top_parent != disk->src &&
         qemuDomainPrepareDiskChainElement(driver, vm, top_parent,
                                           VIR_DISK_CHAIN_READ_WRITE) < 0))
        goto endjob;

    if (flags & VIR_DOMAIN_BLOCK_COMMIT_RELATIVE &&
        topSource != disk->src) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CHANGE_BACKING_FILE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support relative blockpull"));
            goto endjob;
        }

        if (virStorageFileGetRelativeBackingPath(topSource, baseSource,
                                                 &backingPath) < 0)
            goto endjob;

        if (!backingPath) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("can't keep relative backing relationship"));
            goto endjob;
        }
    }

    /* Start the commit operation.  Pass the user's original spelling,
     * if any, through to qemu, since qemu may behave differently
     * depending on whether the input was specified as relative or
     * absolute (that is, our absolute top_canon may do the wrong
     * thing if the user specified a relative name).  Be prepared for
     * a ready event to occur while locks are dropped.  */
    if (mirror) {
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
        disk->mirror = mirror;
        disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT;
    }
    qemuDomainObjEnterMonitor(driver, vm);
    basePath = qemuMonitorDiskNameLookup(priv->mon, device, disk->src,
                                         baseSource);
    topPath = qemuMonitorDiskNameLookup(priv->mon, device, disk->src,
                                        topSource);
    if (basePath && topPath)
        ret = qemuMonitorBlockCommit(priv->mon, device,
                                     topPath, basePath, backingPath,
                                     speed);
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        ret = -1;
        goto endjob;
    }

    if (ret == 0)
        QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob = true;

    if (mirror) {
        if (ret == 0) {
            virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

            mirror = NULL;
            if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
                VIR_WARN("Unable to save status on vm %s after block job",
                         vm->def->name);
            virObjectUnref(cfg);
        } else {
            disk->mirror = NULL;
            disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
        }
    }

 endjob:
    if (ret < 0 && clean_access) {
        /* Revert access to read-only, if possible.  */
        qemuDomainPrepareDiskChainElement(driver, vm, baseSource,
                                          VIR_DISK_CHAIN_READ_ONLY);
        if (top_parent && top_parent != disk->src)
            qemuDomainPrepareDiskChainElement(driver, vm, top_parent,
                                              VIR_DISK_CHAIN_READ_ONLY);
    }
    virStorageSourceFree(mirror);
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(topPath);
    VIR_FREE(basePath);
    VIR_FREE(backingPath);
    VIR_FREE(device);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainOpenGraphics(virDomainPtr dom,
                       unsigned int idx,
                       int fd,
                       unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    const char *protocol;

    virCheckFlags(VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainOpenGraphicsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (idx >= vm->def->ngraphics) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No graphics backend with index %d"), idx);
        goto cleanup;
    }
    switch (vm->def->graphics[idx]->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        protocol = "vnc";
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        protocol = "spice";
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Can only open VNC or SPICE graphics backends, not %s"),
                       virDomainGraphicsTypeToString(vm->def->graphics[idx]->type));
        goto cleanup;
    }

    if (virSecurityManagerSetImageFDLabel(driver->securityManager, vm->def,
                                          fd) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorOpenGraphics(priv->mon, protocol, fd, "graphicsfd",
                                  (flags & VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH) != 0);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainOpenGraphicsFD(virDomainPtr dom,
                         unsigned int idx,
                         unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    const char *protocol;
    int pair[2] = {-1, -1};

    virCheckFlags(VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainOpenGraphicsFdEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (idx >= vm->def->ngraphics) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No graphics backend with index %d"), idx);
        goto cleanup;
    }
    switch (vm->def->graphics[idx]->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        protocol = "vnc";
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        protocol = "spice";
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Can only open VNC or SPICE graphics backends, not %s"),
                       virDomainGraphicsTypeToString(vm->def->graphics[idx]->type));
        goto cleanup;
    }

    if (virSecurityManagerSetSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, pair) < 0)
        goto cleanup;

    if (virSecurityManagerClearSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorOpenGraphics(priv->mon, protocol, pair[1], "graphicsfd",
                                  (flags & VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH));
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    qemuDomainObjEndJob(driver, vm);
    if (ret < 0)
        goto cleanup;

    ret = pair[0];
    pair[0] = -1;

 cleanup:
    VIR_FORCE_CLOSE(pair[0]);
    VIR_FORCE_CLOSE(pair[1]);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainSetBlockIoTune(virDomainPtr dom,
                         const char *disk,
                         virTypedParameterPtr params,
                         int nparams,
                         unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv;
    virDomainDefPtr persistentDef = NULL;
    virDomainBlockIoTuneInfo info;
    virDomainBlockIoTuneInfo *oldinfo;
    char *device = NULL;
    int ret = -1;
    size_t i;
    int idx = -1;
    virDomainDiskDefPtr conf_disk = NULL;
    bool set_bytes = false;
    bool set_iops = false;
    bool set_bytes_max = false;
    bool set_iops_max = false;
    bool set_size_iops = false;
    bool supportMaxOptions = true;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    virObjectEventPtr event = NULL;
    virTypedParameterPtr eventParams = NULL;
    int eventNparams = 0;
    int eventMaxparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC,
                               VIR_TYPED_PARAM_ULLONG,
                               NULL) < 0)
        return -1;

    memset(&info, 0, sizeof(info));

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainSetBlockIoTuneEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto endjob;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;

    if (virTypedParamsAddString(&eventParams, &eventNparams, &eventMaxparams,
                                VIR_DOMAIN_TUNABLE_BLKDEV_DISK, disk) < 0)
        goto endjob;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (param->value.ul > LLONG_MAX) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("block I/O throttle limit value must"
                             " be less than %llu"), LLONG_MAX);
            goto endjob;
        }

        if (STREQ(param->field, VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC)) {
            info.total_bytes_sec = param->value.ul;
            set_bytes = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC)) {
            info.read_bytes_sec = param->value.ul;
            set_bytes = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC)) {
            info.write_bytes_sec = param->value.ul;
            set_bytes = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC)) {
            info.total_iops_sec = param->value.ul;
            set_iops = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC)) {
            info.read_iops_sec = param->value.ul;
            set_iops = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC)) {
            info.write_iops_sec = param->value.ul;
            set_iops = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX)) {
            info.total_bytes_sec_max = param->value.ul;
            set_bytes_max = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX)) {
            info.read_bytes_sec_max = param->value.ul;
            set_bytes_max = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX)) {
            info.write_bytes_sec_max = param->value.ul;
            set_bytes_max = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX)) {
            info.total_iops_sec_max = param->value.ul;
            set_iops_max = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX)) {
            info.read_iops_sec_max = param->value.ul;
            set_iops_max = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX)) {
            info.write_iops_sec_max = param->value.ul;
            set_iops_max = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX,
                                        param->value.ul) < 0)
                goto endjob;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC)) {
            info.size_iops_sec = param->value.ul;
            set_size_iops = true;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_BLKDEV_SIZE_IOPS_SEC,
                                        param->value.ul) < 0)
                goto endjob;
        }
    }

    if ((info.total_bytes_sec && info.read_bytes_sec) ||
        (info.total_bytes_sec && info.write_bytes_sec)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("total and read/write of bytes_sec "
                         "cannot be set at the same time"));
        goto endjob;
    }

    if ((info.total_iops_sec && info.read_iops_sec) ||
        (info.total_iops_sec && info.write_iops_sec)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("total and read/write of iops_sec "
                         "cannot be set at the same time"));
        goto endjob;
    }

    if ((info.total_bytes_sec_max && info.read_bytes_sec_max) ||
        (info.total_bytes_sec_max && info.write_bytes_sec_max)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("total and read/write of bytes_sec_max "
                         "cannot be set at the same time"));
        goto endjob;
    }

    if ((info.total_iops_sec_max && info.read_iops_sec_max) ||
        (info.total_iops_sec_max && info.write_iops_sec_max)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("total and read/write of iops_sec_max "
                         "cannot be set at the same time"));
        goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!(conf_disk = virDomainDiskByName(persistentDef, disk, true))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing persistent configuration for disk '%s'"),
                           disk);
            goto endjob;
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        supportMaxOptions = virQEMUCapsGet(priv->qemuCaps,
                                           QEMU_CAPS_DRIVE_IOTUNE_MAX);
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_IOTUNE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block I/O throttling not supported with this "
                         "QEMU binary"));
            goto endjob;
        }

        if (!supportMaxOptions &&
            (set_iops_max || set_bytes_max || set_size_iops)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("a block I/O throttling parameter is not "
                             "supported with this QEMU binary"));
             goto endjob;
        }

        if (!(device = qemuDiskPathToAlias(vm, disk, &idx)))
            goto endjob;

        /* If the user didn't specify bytes limits, inherit previous
         * values; likewise if the user didn't specify iops
         * limits.  */
        oldinfo = &vm->def->disks[idx]->blkdeviotune;
        if (!set_bytes) {
            info.total_bytes_sec = oldinfo->total_bytes_sec;
            info.read_bytes_sec = oldinfo->read_bytes_sec;
            info.write_bytes_sec = oldinfo->write_bytes_sec;
        }
        if (!set_bytes_max) {
            info.total_bytes_sec_max = oldinfo->total_bytes_sec_max;
            info.read_bytes_sec_max = oldinfo->read_bytes_sec_max;
            info.write_bytes_sec_max = oldinfo->write_bytes_sec_max;
        }
        if (!set_iops) {
            info.total_iops_sec = oldinfo->total_iops_sec;
            info.read_iops_sec = oldinfo->read_iops_sec;
            info.write_iops_sec = oldinfo->write_iops_sec;
        }
        if (!set_iops_max) {
            info.total_iops_sec_max = oldinfo->total_iops_sec_max;
            info.read_iops_sec_max = oldinfo->read_iops_sec_max;
            info.write_iops_sec_max = oldinfo->write_iops_sec_max;
        }
        if (!set_size_iops)
            info.size_iops_sec = oldinfo->size_iops_sec;
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSetBlockIoThrottle(priv->mon, device,
                                            &info, supportMaxOptions);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;
        if (ret < 0)
            goto endjob;
        vm->def->disks[idx]->blkdeviotune = info;

        ret = virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm);
        if (ret < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Saving live XML config failed"));
            goto endjob;
        }

        if (eventNparams) {
            event = virDomainEventTunableNewFromDom(dom, eventParams, eventNparams);
            eventNparams = 0;
            qemuDomainEventQueue(driver, event);
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        oldinfo = &conf_disk->blkdeviotune;
        if (!set_bytes) {
            info.total_bytes_sec = oldinfo->total_bytes_sec;
            info.read_bytes_sec = oldinfo->read_bytes_sec;
            info.write_bytes_sec = oldinfo->write_bytes_sec;
        }
        if (!set_iops) {
            info.total_iops_sec = oldinfo->total_iops_sec;
            info.read_iops_sec = oldinfo->read_iops_sec;
            info.write_iops_sec = oldinfo->write_iops_sec;
        }
        conf_disk->blkdeviotune = info;
        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        if (ret < 0) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Write to config file failed"));
            goto endjob;
        }
    }

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(device);
    virDomainObjEndAPI(&vm);
    if (eventNparams)
        virTypedParamsFree(eventParams, eventNparams);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetBlockIoTune(virDomainPtr dom,
                         const char *disk,
                         virTypedParameterPtr params,
                         int *nparams,
                         unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv = NULL;
    virDomainDefPtr persistentDef = NULL;
    virDomainBlockIoTuneInfo reply;
    char *device = NULL;
    int ret = -1;
    size_t i;
    virCapsPtr caps = NULL;
    bool supportMaxOptions = true;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetBlockIoTuneEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;
    sa_assert((flags & VIR_DOMAIN_AFFECT_LIVE) ||
              (flags & VIR_DOMAIN_AFFECT_CONFIG));

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If the VM is running, we can check if the current VM can use
         * optional parameters or not. We didn't made this check sooner
         * because we need vm->privateData which need
         * virDomainLiveConfigHelperMethod to do so. */
        priv = vm->privateData;
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_IOTUNE)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("block I/O throttling not supported with this "
                         "QEMU binary"));
            goto endjob;
        }
        supportMaxOptions = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_IOTUNE_MAX);
    }

    if ((*nparams) == 0) {
        *nparams = supportMaxOptions ?
                   QEMU_NB_BLOCK_IO_TUNE_PARAM_MAX : QEMU_NB_BLOCK_IO_TUNE_PARAM;
        ret = 0;
        goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        device = qemuDiskPathToAlias(vm, disk, NULL);
        if (!device)
            goto endjob;
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorGetBlockIoThrottle(priv->mon, device, &reply, supportMaxOptions);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto endjob;
        if (ret < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        virDomainDiskDefPtr diskDef;
        if (!(diskDef = virDomainDiskByName(persistentDef, disk, true))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("disk '%s' was not found in the domain config"),
                           disk);
            goto endjob;
        }
        reply = diskDef->blkdeviotune;
    }

    for (i = 0; i < QEMU_NB_BLOCK_IO_TUNE_PARAM_MAX && i < *nparams; i++) {
        virTypedParameterPtr param = &params[i];

        switch (i) {
        case 0:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.total_bytes_sec) < 0)
                goto endjob;
            break;
        case 1:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.read_bytes_sec) < 0)
                goto endjob;
            break;
        case 2:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.write_bytes_sec) < 0)
                goto endjob;
            break;
        case 3:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.total_iops_sec) < 0)
                goto endjob;
            break;
        case 4:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.read_iops_sec) < 0)
                goto endjob;
            break;
        case 5:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.write_iops_sec) < 0)
                goto endjob;
            break;
        case 6:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.total_bytes_sec_max) < 0)
                goto endjob;
            break;
        case 7:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.read_bytes_sec_max) < 0)
                goto endjob;
            break;
        case 8:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.write_bytes_sec_max) < 0)
                goto endjob;
            break;
        case 9:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.total_iops_sec_max) < 0)
                goto endjob;
            break;
        case 10:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.read_iops_sec_max) < 0)
                goto endjob;
            break;
        case 11:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.write_iops_sec_max) < 0)
                goto endjob;
            break;
        case 12:
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC,
                                        VIR_TYPED_PARAM_ULLONG,
                                        reply.size_iops_sec) < 0)
                goto endjob;
        /* coverity[dead_error_begin] */
        default:
            break;
        }
    }

    if (!supportMaxOptions && *nparams > QEMU_NB_BLOCK_IO_TUNE_PARAM)
        *nparams = QEMU_NB_BLOCK_IO_TUNE_PARAM;
    else if (*nparams > QEMU_NB_BLOCK_IO_TUNE_PARAM_MAX)
        *nparams = QEMU_NB_BLOCK_IO_TUNE_PARAM_MAX;
    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(device);
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    return ret;
}

static int
qemuDomainGetDiskErrors(virDomainPtr dom,
                        virDomainDiskErrorPtr errors,
                        unsigned int nerrors,
                        unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv;
    virHashTablePtr table = NULL;
    int ret = -1;
    size_t i;
    int n = 0;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetDiskErrorsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!errors) {
        ret = vm->def->ndisks;
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    table = qemuMonitorGetBlockInfo(priv->mon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto endjob;
    if (!table)
        goto endjob;

    for (i = n = 0; i < vm->def->ndisks; i++) {
        struct qemuDomainDiskInfo *info;
        virDomainDiskDefPtr disk = vm->def->disks[i];

        if ((info = virHashLookup(table, disk->info.alias)) &&
            info->io_status != VIR_DOMAIN_DISK_ERROR_NONE) {
            if (n == nerrors)
                break;

            if (VIR_STRDUP(errors[n].disk, disk->dst) < 0)
                goto endjob;
            errors[n].error = info->io_status;
            n++;
        }
    }

    ret = n;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virHashFree(table);
    if (ret < 0) {
        for (i = 0; i < n; i++)
            VIR_FREE(errors[i].disk);
    }
    return ret;
}

static int
qemuDomainSetMetadata(virDomainPtr dom,
                      int type,
                      const char *metadata,
                      const char *key,
                      const char *uri,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetMetadataEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri, caps,
                                  driver->xmlopt, cfg->stateDir,
                                  cfg->configDir, flags);

    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static char *
qemuDomainGetMetadata(virDomainPtr dom,
                      int type,
                      const char *uri,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetMetadataEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    ret = virDomainObjGetMetadata(vm, type, uri, caps, driver->xmlopt, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    return ret;
}


static int
qemuDomainGetCPUStats(virDomainPtr domain,
                      virTypedParameterPtr params,
                      unsigned int nparams,
                      int start_cpu,
                      unsigned int ncpus,
                      unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    bool isActive;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        return -1;

    priv = vm->privateData;

    if (virDomainGetCPUStatsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    isActive = virDomainObjIsActive(vm);
    if (!isActive) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto cleanup;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUACCT)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cgroup CPUACCT controller is not mounted"));
        goto cleanup;
    }

    if (start_cpu == -1)
        ret = virCgroupGetDomainTotalCpuStats(priv->cgroup,
                                              params, nparams);
    else
        ret = virCgroupGetPercpuStats(priv->cgroup, params, nparams,
                                      start_cpu, ncpus, priv->nvcpupids);
 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainPMSuspendForDuration(virDomainPtr dom,
                               unsigned int target,
                               unsigned long long duration,
                               unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (duration) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Duration not supported. Use 0 for now"));
        return -1;
    }

    if (!(target == VIR_NODE_SUSPEND_TARGET_MEM ||
          target == VIR_NODE_SUSPEND_TARGET_DISK ||
          target == VIR_NODE_SUSPEND_TARGET_HYBRID)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unknown suspend target: %u"),
                       target);
        return -1;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainPMSuspendForDurationEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_WAKEUP) &&
        (target == VIR_NODE_SUSPEND_TARGET_MEM ||
         target == VIR_NODE_SUSPEND_TARGET_HYBRID)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Unable to suspend domain due to "
                         "missing system_wakeup monitor command"));
        goto cleanup;
    }

    if (vm->def->pm.s3 || vm->def->pm.s4) {
        if (vm->def->pm.s3 == VIR_TRISTATE_BOOL_NO &&
            (target == VIR_NODE_SUSPEND_TARGET_MEM ||
             target == VIR_NODE_SUSPEND_TARGET_HYBRID)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("S3 state is disabled for this domain"));
            goto cleanup;
        }

        if (vm->def->pm.s4 == VIR_TRISTATE_BOOL_NO &&
            target == VIR_NODE_SUSPEND_TARGET_DISK) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("S4 state is disabled for this domain"));
            goto cleanup;
        }
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!qemuDomainAgentAvailable(vm, true))
        goto endjob;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterAgent(vm);
    ret = qemuAgentSuspend(priv->agent, target);
    qemuDomainObjExitAgent(vm);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainPMWakeup(virDomainPtr dom,
                   unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPMWakeupEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_WAKEUP)) {
       virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                      _("Unable to wake up domain due to "
                        "missing system_wakeup monitor command"));
       goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSystemWakeup(priv->mon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuConnectListAllDomains(virConnectPtr conn,
                          virDomainPtr **domains,
                          unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        goto cleanup;

    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 virConnectListAllDomainsCheckACL, flags);

 cleanup:
    return ret;
}

static char *
qemuDomainQemuAgentCommand(virDomainPtr domain,
                           const char *cmd,
                           int timeout,
                           unsigned int flags)
{
    virQEMUDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    char *result = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, NULL);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainQemuAgentCommandEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!qemuDomainAgentAvailable(vm, true))
        goto endjob;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterAgent(vm);
    ret = qemuAgentArbitraryCommand(priv->agent, cmd, &result, timeout);
    qemuDomainObjExitAgent(vm);
    if (ret < 0)
        VIR_FREE(result);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return result;
}


static int
qemuConnectDomainQemuMonitorEventRegister(virConnectPtr conn,
                                          virDomainPtr dom,
                                          const char *event,
                                          virConnectDomainQemuMonitorEventCallback callback,
                                          void *opaque,
                                          virFreeCallback freecb,
                                          unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectDomainQemuMonitorEventRegisterEnsureACL(conn) < 0)
        goto cleanup;

    if (virDomainQemuMonitorEventStateRegisterID(conn,
                                                 driver->domainEventState,
                                                 dom, event, callback,
                                                 opaque, freecb, flags,
                                                 &ret) < 0)
        ret = -1;

 cleanup:
    return ret;
}


static int
qemuConnectDomainQemuMonitorEventDeregister(virConnectPtr conn,
                                            int callbackID)
{
    virQEMUDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectDomainQemuMonitorEventDeregisterEnsureACL(conn) < 0)
        goto cleanup;

    if (virObjectEventStateDeregisterID(conn, driver->domainEventState,
                                        callbackID) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int
qemuDomainFSTrim(virDomainPtr dom,
                 const char *mountPoint,
                 unsigned long long minimum,
                 unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (mountPoint) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Specifying mount point "
                         "is not supported for now"));
        return -1;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainFSTrimEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!qemuDomainAgentAvailable(vm, true))
        goto endjob;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterAgent(vm);
    ret = qemuAgentFSTrim(priv->agent, minimum);
    qemuDomainObjExitAgent(vm);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuNodeGetInfo(virConnectPtr conn,
                virNodeInfoPtr nodeinfo)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return nodeGetInfo(NULL, nodeinfo);
}


static int
qemuNodeGetCPUStats(virConnectPtr conn,
                    int cpuNum,
                    virNodeCPUStatsPtr params,
                    int *nparams,
                    unsigned int flags)
{
    if (virNodeGetCPUStatsEnsureACL(conn) < 0)
        return -1;

    return nodeGetCPUStats(cpuNum, params, nparams, flags);
}


static int
qemuNodeGetMemoryStats(virConnectPtr conn,
                       int cellNum,
                       virNodeMemoryStatsPtr params,
                       int *nparams,
                       unsigned int flags)
{
    if (virNodeGetMemoryStatsEnsureACL(conn) < 0)
        return -1;

    return nodeGetMemoryStats(NULL, cellNum, params, nparams, flags);
}


static int
qemuNodeGetCellsFreeMemory(virConnectPtr conn,
                           unsigned long long *freeMems,
                           int startCell,
                           int maxCells)
{
    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        return -1;

    return nodeGetCellsFreeMemory(freeMems, startCell, maxCells);
}


static unsigned long long
qemuNodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long freeMem;

    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    if (nodeGetMemory(NULL, &freeMem) < 0)
        return 0;

    return freeMem;
}


static int
qemuNodeGetMemoryParameters(virConnectPtr conn,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    if (virNodeGetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return nodeGetMemoryParameters(params, nparams, flags);
}


static int
qemuNodeSetMemoryParameters(virConnectPtr conn,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    if (virNodeSetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return nodeSetMemoryParameters(params, nparams, flags);
}


static int
qemuNodeGetCPUMap(virConnectPtr conn,
                  unsigned char **cpumap,
                  unsigned int *online,
                  unsigned int flags)
{
    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    return nodeGetCPUMap(NULL, cpumap, online, flags);
}


static int
qemuNodeSuspendForDuration(virConnectPtr conn,
                           unsigned int target,
                           unsigned long long duration,
                           unsigned int flags)
{
    if (virNodeSuspendForDurationEnsureACL(conn) < 0)
        return -1;

    return nodeSuspendForDuration(target, duration, flags);
}

static int
qemuConnectGetCPUModelNames(virConnectPtr conn,
                            const char *arch,
                            char ***models,
                            unsigned int flags)
{
    virCheckFlags(0, -1);
    if (virConnectGetCPUModelNamesEnsureACL(conn) < 0)
        return -1;

    return cpuGetModels(arch, models);
}

static int
qemuDomainGetTime(virDomainPtr dom,
                  long long *seconds,
                  unsigned int *nseconds,
                  unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;
    int rv;

    virCheckFlags(0, ret);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return ret;

    if (virDomainGetTimeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!qemuDomainAgentAvailable(vm, true))
        goto endjob;

    qemuDomainObjEnterAgent(vm);
    rv = qemuAgentGetTime(priv->agent, seconds, nseconds);
    qemuDomainObjExitAgent(vm);

    if (rv < 0)
        goto endjob;

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainSetTime(virDomainPtr dom,
                  long long seconds,
                  unsigned int nseconds,
                  unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    bool rtcSync = flags & VIR_DOMAIN_TIME_SYNC;
    int ret = -1;
    int rv;

    virCheckFlags(VIR_DOMAIN_TIME_SYNC, ret);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return ret;

    if (virDomainSetTimeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    /* On x86, the rtc-reset-reinjection QMP command must be called after
     * setting the time to avoid trouble down the line. If the command is
     * not available, don't set the time at all and report an error */
    if (ARCH_IS_X86(vm->def->os.arch) &&
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_RTC_RESET_REINJECTION))
    {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot set time: qemu doesn't support "
                         "rtc-reset-reinjection command"));
        goto endjob;
    }

    if (!qemuDomainAgentAvailable(vm, true))
        goto endjob;

    qemuDomainObjEnterAgent(vm);
    rv = qemuAgentSetTime(priv->agent, seconds, nseconds, rtcSync);
    qemuDomainObjExitAgent(vm);

    if (rv < 0)
        goto endjob;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    /* Don't try to call rtc-reset-reinjection if it's not available */
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_RTC_RESET_REINJECTION)) {
        qemuDomainObjEnterMonitor(driver, vm);
        rv = qemuMonitorRTCResetReinjection(priv->mon);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto endjob;

        if (rv < 0)
            goto endjob;
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainFSFreeze(virDomainPtr dom,
                   const char **mountpoints,
                   unsigned int nmountpoints,
                   unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainFSFreezeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    ret = qemuDomainSnapshotFSFreeze(driver, vm, mountpoints, nmountpoints);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuDomainFSThaw(virDomainPtr dom,
                 const char **mountpoints,
                 unsigned int nmountpoints,
                 unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (mountpoints || nmountpoints) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("specifying mountpoints is not supported"));
        return ret;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainFSThawEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    ret = qemuDomainSnapshotFSThaw(driver, vm, true);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuNodeGetFreePages(virConnectPtr conn,
                     unsigned int npages,
                     unsigned int *pages,
                     int startCell,
                     unsigned int cellCount,
                     unsigned long long *counts,
                     unsigned int flags)
{
    virCheckFlags(0, -1);

    if (virNodeGetFreePagesEnsureACL(conn) < 0)
        return -1;

    return nodeGetFreePages(npages, pages, startCell, cellCount, counts);
}


static char *
qemuConnectGetDomainCapabilities(virConnectPtr conn,
                                 const char *emulatorbin,
                                 const char *arch_str,
                                 const char *machine,
                                 const char *virttype_str,
                                 unsigned int flags)
{
    char *ret = NULL;
    virQEMUDriverPtr driver = conn->privateData;
    virQEMUCapsPtr qemuCaps = NULL;
    int virttype; /* virDomainVirtType */
    virDomainCapsPtr domCaps = NULL;
    int arch = virArchFromHost(); /* virArch */
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(0, ret);

    if (virConnectGetDomainCapabilitiesEnsureACL(conn) < 0)
        return ret;

    cfg = virQEMUDriverGetConfig(driver);

    if (qemuHostdevHostSupportsPassthroughLegacy())
        virttype = VIR_DOMAIN_VIRT_KVM;
    else
        virttype = VIR_DOMAIN_VIRT_QEMU;

    if (virttype_str &&
        (virttype = virDomainVirtTypeFromString(virttype_str)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %s"),
                       virttype_str);
        goto cleanup;
    }

    if (arch_str && (arch = virArchFromString(arch_str)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown architecture: %s"),
                       arch_str);
        goto cleanup;
    }

    if (emulatorbin) {
        virArch arch_from_caps;

        if (!(qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache,
                                                emulatorbin)))
            goto cleanup;

        arch_from_caps = virQEMUCapsGetArch(qemuCaps);

        if (arch_from_caps != arch &&
            !((ARCH_IS_X86(arch) && ARCH_IS_X86(arch_from_caps)) ||
              (ARCH_IS_PPC(arch) && ARCH_IS_PPC(arch_from_caps)) ||
              (ARCH_IS_ARM(arch) && ARCH_IS_ARM(arch_from_caps)) ||
              (ARCH_IS_S390(arch) && ARCH_IS_S390(arch_from_caps)))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("architecture from emulator '%s' doesn't "
                             "match given architecture '%s'"),
                           virArchToString(arch_from_caps),
                           virArchToString(arch));
            goto cleanup;
        }
    } else {
        if (!(qemuCaps = virQEMUCapsCacheLookupByArch(driver->qemuCapsCache,
                                                      arch))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unable to find any emulator to serve '%s' "
                             "architecture"), virArchToString(arch));
            goto cleanup;
        }

        emulatorbin = virQEMUCapsGetBinary(qemuCaps);
    }

    if (machine) {
        /* Turn @machine into canonical name */
        machine = virQEMUCapsGetCanonicalMachine(qemuCaps, machine);

        if (!virQEMUCapsIsMachineSupported(qemuCaps, machine)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("the machine '%s' is not supported by emulator '%s'"),
                           machine, emulatorbin);
            goto cleanup;
        }
    } else {
        machine = virQEMUCapsGetDefaultMachine(qemuCaps);
    }

    if (!(domCaps = virDomainCapsNew(emulatorbin, machine, arch, virttype)))
        goto cleanup;

    if (virQEMUCapsFillDomainCaps(domCaps, qemuCaps,
                                  cfg->loader, cfg->nloader) < 0)
        goto cleanup;

    ret = virDomainCapsFormat(domCaps);
 cleanup:
    virObjectUnref(cfg);
    virObjectUnref(domCaps);
    virObjectUnref(qemuCaps);
    return ret;
}


static int
qemuDomainGetStatsState(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                        virDomainObjPtr dom,
                        virDomainStatsRecordPtr record,
                        int *maxparams,
                        unsigned int privflags ATTRIBUTE_UNUSED)
{
    if (virTypedParamsAddInt(&record->params,
                             &record->nparams,
                             maxparams,
                             "state.state",
                             dom->state.state) < 0)
        return -1;

    if (virTypedParamsAddInt(&record->params,
                             &record->nparams,
                             maxparams,
                             "state.reason",
                             dom->state.reason) < 0)
        return -1;

    return 0;
}


typedef enum {
    QEMU_DOMAIN_STATS_HAVE_JOB = 1 << 0, /* job is entered, monitor can be
                                            accessed */
    QEMU_DOMAIN_STATS_BACKING  = 1 << 1, /* include backing chain in
                                            block stats */
} qemuDomainStatsFlags;


#define HAVE_JOB(flags) ((flags) & QEMU_DOMAIN_STATS_HAVE_JOB)


static int
qemuDomainGetStatsCpu(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                      virDomainObjPtr dom,
                      virDomainStatsRecordPtr record,
                      int *maxparams,
                      unsigned int privflags ATTRIBUTE_UNUSED)
{
    qemuDomainObjPrivatePtr priv = dom->privateData;
    unsigned long long cpu_time = 0;
    unsigned long long user_time = 0;
    unsigned long long sys_time = 0;
    int err = 0;

    if (!priv->cgroup)
        return 0;

    err = virCgroupGetCpuacctUsage(priv->cgroup, &cpu_time);
    if (!err && virTypedParamsAddULLong(&record->params,
                                        &record->nparams,
                                        maxparams,
                                        "cpu.time",
                                        cpu_time) < 0)
        return -1;

    err = virCgroupGetCpuacctStat(priv->cgroup, &user_time, &sys_time);
    if (!err && virTypedParamsAddULLong(&record->params,
                                        &record->nparams,
                                        maxparams,
                                        "cpu.user",
                                        user_time) < 0)
        return -1;
    if (!err && virTypedParamsAddULLong(&record->params,
                                        &record->nparams,
                                        maxparams,
                                        "cpu.system",
                                        sys_time) < 0)
        return -1;

    return 0;
}

static int
qemuDomainGetStatsBalloon(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                          virDomainObjPtr dom,
                          virDomainStatsRecordPtr record,
                          int *maxparams,
                          unsigned int privflags ATTRIBUTE_UNUSED)
{
    qemuDomainObjPrivatePtr priv = dom->privateData;
    unsigned long long cur_balloon = 0;
    int err = 0;

    if (dom->def->memballoon &&
        dom->def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_NONE) {
        cur_balloon = virDomainDefGetMemoryActual(dom->def);
    } else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BALLOON_EVENT)) {
        cur_balloon = dom->def->mem.cur_balloon;
    } else {
        err = -1;
    }

    if (!err && virTypedParamsAddULLong(&record->params,
                                        &record->nparams,
                                        maxparams,
                                        "balloon.current",
                                        cur_balloon) < 0)
        return -1;

    if (virTypedParamsAddULLong(&record->params,
                                &record->nparams,
                                maxparams,
                                "balloon.maximum",
                                virDomainDefGetMemoryActual(dom->def)) < 0)
        return -1;

    return 0;
}


static int
qemuDomainGetStatsVcpu(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                       virDomainObjPtr dom,
                       virDomainStatsRecordPtr record,
                       int *maxparams,
                       unsigned int privflags ATTRIBUTE_UNUSED)
{
    size_t i;
    int ret = -1;
    char param_name[VIR_TYPED_PARAM_FIELD_LENGTH];
    virVcpuInfoPtr cpuinfo = NULL;

    if (virTypedParamsAddUInt(&record->params,
                              &record->nparams,
                              maxparams,
                              "vcpu.current",
                              virDomainDefGetVcpus(dom->def)) < 0)
        return -1;

    if (virTypedParamsAddUInt(&record->params,
                              &record->nparams,
                              maxparams,
                              "vcpu.maximum",
                              virDomainDefGetVcpusMax(dom->def)) < 0)
        return -1;

    if (VIR_ALLOC_N(cpuinfo, virDomainDefGetVcpus(dom->def)) < 0)
        return -1;

    if (qemuDomainHelperGetVcpus(dom, cpuinfo, virDomainDefGetVcpus(dom->def),
                                 NULL, 0) < 0) {
        virResetLastError();
        ret = 0; /* it's ok to be silent and go ahead */
        goto cleanup;
    }

    for (i = 0; i < virDomainDefGetVcpus(dom->def); i++) {
        snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
                 "vcpu.%zu.state", i);
        if (virTypedParamsAddInt(&record->params,
                                 &record->nparams,
                                 maxparams,
                                 param_name,
                                 cpuinfo[i].state) < 0)
            goto cleanup;

        /* stats below are available only if the VM is alive */
        if (!virDomainObjIsActive(dom))
            continue;

        snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
                 "vcpu.%zu.time", i);
        if (virTypedParamsAddULLong(&record->params,
                                    &record->nparams,
                                    maxparams,
                                    param_name,
                                    cpuinfo[i].cpuTime) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cpuinfo);
    return ret;
}

#define QEMU_ADD_COUNT_PARAM(record, maxparams, type, count) \
do { \
    char param_name[VIR_TYPED_PARAM_FIELD_LENGTH]; \
    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH, "%s.count", type); \
    if (virTypedParamsAddUInt(&(record)->params, \
                              &(record)->nparams, \
                              maxparams, \
                              param_name, \
                              count) < 0) \
        goto cleanup; \
} while (0)

#define QEMU_ADD_NAME_PARAM(record, maxparams, type, subtype, num, name) \
do { \
    char param_name[VIR_TYPED_PARAM_FIELD_LENGTH]; \
    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH, \
             "%s.%zu.%s", type, num, subtype); \
    if (virTypedParamsAddString(&(record)->params, \
                                &(record)->nparams, \
                                maxparams, \
                                param_name, \
                                name) < 0) \
        goto cleanup; \
} while (0)

#define QEMU_ADD_NET_PARAM(record, maxparams, num, name, value) \
do { \
    char param_name[VIR_TYPED_PARAM_FIELD_LENGTH]; \
    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH, \
             "net.%zu.%s", num, name); \
    if (value >= 0 && virTypedParamsAddULLong(&(record)->params, \
                                              &(record)->nparams, \
                                              maxparams, \
                                              param_name, \
                                              value) < 0) \
        return -1; \
} while (0)

static int
qemuDomainGetStatsInterface(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                            virDomainObjPtr dom,
                            virDomainStatsRecordPtr record,
                            int *maxparams,
                            unsigned int privflags ATTRIBUTE_UNUSED)
{
    size_t i;
    struct _virDomainInterfaceStats tmp;
    int ret = -1;

    if (!virDomainObjIsActive(dom))
        return 0;

    QEMU_ADD_COUNT_PARAM(record, maxparams, "net", dom->def->nnets);

    /* Check the path is one of the domain's network interfaces. */
    for (i = 0; i < dom->def->nnets; i++) {
        if (!dom->def->nets[i]->ifname)
            continue;

        memset(&tmp, 0, sizeof(tmp));

        QEMU_ADD_NAME_PARAM(record, maxparams,
                            "net", "name", i, dom->def->nets[i]->ifname);

        if (virNetInterfaceStats(dom->def->nets[i]->ifname, &tmp) < 0) {
            virResetLastError();
            continue;
        }

        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "rx.bytes", tmp.rx_bytes);
        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "rx.pkts", tmp.rx_packets);
        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "rx.errs", tmp.rx_errs);
        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "rx.drop", tmp.rx_drop);
        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "tx.bytes", tmp.tx_bytes);
        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "tx.pkts", tmp.tx_packets);
        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "tx.errs", tmp.tx_errs);
        QEMU_ADD_NET_PARAM(record, maxparams, i,
                           "tx.drop", tmp.tx_drop);
    }

    ret = 0;
 cleanup:
    return ret;
}

#undef QEMU_ADD_NET_PARAM

#define QEMU_ADD_BLOCK_PARAM_UI(record, maxparams, num, name, value) \
    do {                                                             \
        char param_name[VIR_TYPED_PARAM_FIELD_LENGTH];               \
        snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,           \
                 "block.%zu.%s", num, name);                         \
        if (virTypedParamsAddUInt(&(record)->params,                 \
                                  &(record)->nparams,                \
                                  maxparams,                         \
                                  param_name,                        \
                                  value) < 0)                        \
            goto cleanup;                                            \
    } while (0)

/* expects a LL, but typed parameter must be ULL */
#define QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, num, name, value) \
do { \
    char param_name[VIR_TYPED_PARAM_FIELD_LENGTH]; \
    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH, \
             "block.%zu.%s", num, name); \
    if (value >= 0 && virTypedParamsAddULLong(&(record)->params, \
                                              &(record)->nparams, \
                                              maxparams, \
                                              param_name, \
                                              value) < 0) \
        goto cleanup; \
} while (0)

#define QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, num, name, value) \
do { \
    char param_name[VIR_TYPED_PARAM_FIELD_LENGTH]; \
    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH, \
             "block.%zu.%s", num, name); \
    if (virTypedParamsAddULLong(&(record)->params, \
                                &(record)->nparams, \
                                maxparams, \
                                param_name, \
                                value) < 0) \
        goto cleanup; \
} while (0)


static int
qemuDomainGetStatsOneBlock(virQEMUDriverPtr driver,
                           virQEMUDriverConfigPtr cfg,
                           virDomainObjPtr dom,
                           virDomainStatsRecordPtr record,
                           int *maxparams,
                           virDomainDiskDefPtr disk,
                           virStorageSourcePtr src,
                           size_t block_idx,
                           unsigned int backing_idx,
                           bool abbreviated,
                           virHashTablePtr stats)
{
    qemuBlockStats *entry;
    int ret = -1;
    char *alias = NULL;

    if (disk->info.alias)
        alias = qemuDomainStorageAlias(disk->info.alias, backing_idx);

    QEMU_ADD_NAME_PARAM(record, maxparams, "block", "name", block_idx,
                        disk->dst);
    if (virStorageSourceIsLocalStorage(src) && src->path)
        QEMU_ADD_NAME_PARAM(record, maxparams, "block", "path",
                            block_idx, src->path);
    if (backing_idx)
        QEMU_ADD_BLOCK_PARAM_UI(record, maxparams, block_idx, "backingIndex",
                                backing_idx);

    if (abbreviated || !alias || !(entry = virHashLookup(stats, alias))) {
        if (virStorageSourceIsEmpty(src)) {
            ret = 0;
            goto cleanup;
        }

        if (qemuStorageLimitsRefresh(driver, cfg, dom, src) < 0) {
            virResetLastError();
            ret = 0;
            goto cleanup;
        }

        if (src->allocation)
            QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, block_idx,
                                     "allocation", src->allocation);
        if (src->capacity)
            QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, block_idx,
                                     "capacity", src->capacity);
        if (src->physical)
            QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, block_idx,
                                     "physical", src->physical);
        ret = 0;
        goto cleanup;
    }

    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "rd.reqs", entry->rd_req);
    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "rd.bytes", entry->rd_bytes);
    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "rd.times", entry->rd_total_times);
    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "wr.reqs", entry->wr_req);
    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "wr.bytes", entry->wr_bytes);
    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "wr.times", entry->wr_total_times);
    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "fl.reqs", entry->flush_req);
    QEMU_ADD_BLOCK_PARAM_LL(record, maxparams, block_idx,
                            "fl.times", entry->flush_total_times);

    QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, block_idx,
                             "allocation", entry->wr_highest_offset);

    if (entry->capacity)
        QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, block_idx,
                                 "capacity", entry->capacity);
    if (entry->physical) {
        QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, block_idx,
                                 "physical", entry->physical);
    } else {
        if (virStorageSourceUpdateBlockPhysicalSize(src, false) == 0) {
            QEMU_ADD_BLOCK_PARAM_ULL(record, maxparams, block_idx,
                                     "physical", src->physical);
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(alias);
    return ret;
}


static int
qemuDomainGetStatsBlock(virQEMUDriverPtr driver,
                        virDomainObjPtr dom,
                        virDomainStatsRecordPtr record,
                        int *maxparams,
                        unsigned int privflags)
{
    size_t i;
    int ret = -1;
    int rc;
    virHashTablePtr stats = NULL;
    qemuDomainObjPrivatePtr priv = dom->privateData;
    bool abbreviated = false;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int count_index = -1;
    size_t visited = 0;
    bool visitBacking = !!(privflags & QEMU_DOMAIN_STATS_BACKING);

    if (!HAVE_JOB(privflags) || !virDomainObjIsActive(dom)) {
        abbreviated = true; /* it's ok, just go ahead silently */
    } else {
        qemuDomainObjEnterMonitor(driver, dom);
        rc = qemuMonitorGetAllBlockStatsInfo(priv->mon, &stats,
                                             visitBacking);
        if (rc >= 0)
            ignore_value(qemuMonitorBlockStatsUpdateCapacity(priv->mon, stats,
                                                             visitBacking));
        if (qemuDomainObjExitMonitor(driver, dom) < 0)
            goto cleanup;

        if (rc < 0) {
            virResetLastError();
            abbreviated = true; /* still ok, again go ahead silently */
        }
    }

    /* When listing backing chains, it's easier to fix up the count
     * after the iteration than it is to iterate twice; but we still
     * want count listed first.  */
    count_index = record->nparams;
    QEMU_ADD_COUNT_PARAM(record, maxparams, "block", 0);

    for (i = 0; i < dom->def->ndisks; i++) {
        virDomainDiskDefPtr disk = dom->def->disks[i];
        virStorageSourcePtr src = disk->src;
        unsigned int backing_idx = 0;

        while (src && (backing_idx == 0 || visitBacking)) {
            if (qemuDomainGetStatsOneBlock(driver, cfg, dom, record, maxparams,
                                           disk, src, visited, backing_idx,
                                           abbreviated, stats) < 0)
                goto cleanup;
            visited++;
            backing_idx++;
            src = src->backingStore;
        }
    }

    record->params[count_index].value.ui = visited;
    ret = 0;

 cleanup:
    virHashFree(stats);
    virObjectUnref(cfg);
    return ret;
}

#undef QEMU_ADD_BLOCK_PARAM_LL

#undef QEMU_ADD_BLOCK_PARAM_ULL

#undef QEMU_ADD_NAME_PARAM

#undef QEMU_ADD_COUNT_PARAM

typedef int
(*qemuDomainGetStatsFunc)(virQEMUDriverPtr driver,
                          virDomainObjPtr dom,
                          virDomainStatsRecordPtr record,
                          int *maxparams,
                          unsigned int flags);

struct qemuDomainGetStatsWorker {
    qemuDomainGetStatsFunc func;
    unsigned int stats;
    bool monitor;
};

static struct qemuDomainGetStatsWorker qemuDomainGetStatsWorkers[] = {
    { qemuDomainGetStatsState, VIR_DOMAIN_STATS_STATE, false },
    { qemuDomainGetStatsCpu, VIR_DOMAIN_STATS_CPU_TOTAL, false },
    { qemuDomainGetStatsBalloon, VIR_DOMAIN_STATS_BALLOON, true },
    { qemuDomainGetStatsVcpu, VIR_DOMAIN_STATS_VCPU, false },
    { qemuDomainGetStatsInterface, VIR_DOMAIN_STATS_INTERFACE, false },
    { qemuDomainGetStatsBlock, VIR_DOMAIN_STATS_BLOCK, true },
    { NULL, 0, false }
};


static int
qemuDomainGetStatsCheckSupport(unsigned int *stats,
                               bool enforce)
{
    unsigned int supportedstats = 0;
    size_t i;

    for (i = 0; qemuDomainGetStatsWorkers[i].func; i++)
        supportedstats |= qemuDomainGetStatsWorkers[i].stats;

    if (*stats == 0) {
        *stats = supportedstats;
        return 0;
    }

    if (enforce &&
        *stats & ~supportedstats) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("Stats types bits 0x%x are not supported by this daemon"),
                       *stats & ~supportedstats);
        return -1;
    }

    *stats &= supportedstats;
    return 0;
}


static bool
qemuDomainGetStatsNeedMonitor(unsigned int stats)
{
    size_t i;

    for (i = 0; qemuDomainGetStatsWorkers[i].func; i++)
        if (stats & qemuDomainGetStatsWorkers[i].stats &&
            qemuDomainGetStatsWorkers[i].monitor)
            return true;

    return false;
}


static int
qemuDomainGetStats(virConnectPtr conn,
                   virDomainObjPtr dom,
                   unsigned int stats,
                   virDomainStatsRecordPtr *record,
                   unsigned int flags)
{
    int maxparams = 0;
    virDomainStatsRecordPtr tmp;
    size_t i;
    int ret = -1;

    if (VIR_ALLOC(tmp) < 0)
        goto cleanup;

    for (i = 0; qemuDomainGetStatsWorkers[i].func; i++) {
        if (stats & qemuDomainGetStatsWorkers[i].stats) {
            if (qemuDomainGetStatsWorkers[i].func(conn->privateData, dom, tmp,
                                                  &maxparams, flags) < 0)
                goto cleanup;
        }
    }

    if (!(tmp->dom = virGetDomain(conn, dom->def->name, dom->def->uuid)))
        goto cleanup;

    *record = tmp;
    tmp = NULL;
    ret = 0;

 cleanup:
    if (tmp) {
        virTypedParamsFree(tmp->params, tmp->nparams);
        VIR_FREE(tmp);
    }

    return ret;
}


static int
qemuConnectGetAllDomainStats(virConnectPtr conn,
                             virDomainPtr *doms,
                             unsigned int ndoms,
                             unsigned int stats,
                             virDomainStatsRecordPtr **retStats,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virDomainObjPtr *vms = NULL;
    virDomainObjPtr vm;
    size_t nvms;
    virDomainStatsRecordPtr *tmpstats = NULL;
    bool enforce = !!(flags & VIR_CONNECT_GET_ALL_DOMAINS_STATS_ENFORCE_STATS);
    int nstats = 0;
    size_t i;
    int ret = -1;
    unsigned int privflags = 0;
    unsigned int domflags = 0;
    unsigned int lflags = flags & (VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE |
                                   VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT |
                                   VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE);

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE |
                  VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT |
                  VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE |
                  VIR_CONNECT_GET_ALL_DOMAINS_STATS_BACKING |
                  VIR_CONNECT_GET_ALL_DOMAINS_STATS_ENFORCE_STATS, -1);

    if (virConnectGetAllDomainStatsEnsureACL(conn) < 0)
        return -1;

    if (qemuDomainGetStatsCheckSupport(&stats, enforce) < 0)
        return -1;

    if (ndoms) {
        if (virDomainObjListConvert(driver->domains, conn, doms, ndoms, &vms,
                                    &nvms, virConnectGetAllDomainStatsCheckACL,
                                    lflags, true) < 0)
            return -1;
    } else {
        if (virDomainObjListCollect(driver->domains, conn, &vms, &nvms,
                                    virConnectGetAllDomainStatsCheckACL,
                                    lflags) < 0)
            return -1;
    }

    if (VIR_ALLOC_N(tmpstats, nvms + 1) < 0)
        return -1;

    if (qemuDomainGetStatsNeedMonitor(stats))
        privflags |= QEMU_DOMAIN_STATS_HAVE_JOB;

    for (i = 0; i < nvms; i++) {
        virDomainStatsRecordPtr tmp = NULL;
        domflags = 0;
        vm = vms[i];

        virObjectLock(vm);

        if (HAVE_JOB(privflags) &&
            qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) == 0)
            domflags |= QEMU_DOMAIN_STATS_HAVE_JOB;
        /* else: without a job it's still possible to gather some data */

        if (flags & VIR_CONNECT_GET_ALL_DOMAINS_STATS_BACKING)
            domflags |= QEMU_DOMAIN_STATS_BACKING;
        if (qemuDomainGetStats(conn, vm, stats, &tmp, domflags) < 0) {
            if (HAVE_JOB(domflags) && vm)
                qemuDomainObjEndJob(driver, vm);

            virObjectUnlock(vm);
            goto cleanup;
        }

        if (tmp)
            tmpstats[nstats++] = tmp;

        if (HAVE_JOB(domflags))
            qemuDomainObjEndJob(driver, vm);

        virObjectUnlock(vm);
    }

    *retStats = tmpstats;
    tmpstats = NULL;

    ret = nstats;

 cleanup:
    virDomainStatsRecordListFree(tmpstats);
    virObjectListFreeCount(vms, nvms);

    return ret;
}


static int
qemuNodeAllocPages(virConnectPtr conn,
                   unsigned int npages,
                   unsigned int *pageSizes,
                   unsigned long long *pageCounts,
                   int startCell,
                   unsigned int cellCount,
                   unsigned int flags)
{
    bool add = !(flags & VIR_NODE_ALLOC_PAGES_SET);

    virCheckFlags(VIR_NODE_ALLOC_PAGES_SET, -1);

    if (virNodeAllocPagesEnsureACL(conn) < 0)
        return -1;

    return nodeAllocPages(npages, pageSizes, pageCounts,
                          startCell, cellCount, add);
}


static int
qemuDomainGetFSInfo(virDomainPtr dom,
                    virDomainFSInfoPtr **info,
                    unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, ret);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return ret;

    if (virDomainGetFSInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!qemuDomainAgentAvailable(vm, true))
        goto endjob;

    qemuDomainObjEnterAgent(vm);
    ret = qemuAgentGetFSInfo(priv->agent, info, vm->def);
    qemuDomainObjExitAgent(vm);

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuDomainInterfaceAddresses(virDomainPtr dom,
                             virDomainInterfacePtr **ifaces,
                             unsigned int source,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainInterfaceAddressesEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto cleanup;
    }

    switch (source) {
    case VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE:
        ret = qemuGetDHCPInterfaces(dom, vm, ifaces);
        break;

    case VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT:
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
            goto cleanup;

        if (!qemuDomainAgentAvailable(vm, true))
            goto endjob;

        qemuDomainObjEnterAgent(vm);
        ret = qemuAgentGetInterfaces(priv->agent, ifaces);
        qemuDomainObjExitAgent(vm);

    endjob:
        qemuDomainObjEndJob(driver, vm);

        break;

    default:
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("Unknown IP address data source %d"),
                       source);
        break;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
qemuGetDHCPInterfaces(virDomainPtr dom,
                      virDomainObjPtr vm,
                      virDomainInterfacePtr **ifaces)
{
    int rv = -1;
    int n_leases = 0;
    size_t i, j;
    size_t ifaces_count = 0;
    virNetworkPtr network = NULL;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    virDomainInterfacePtr iface = NULL;
    virNetworkDHCPLeasePtr *leases = NULL;
    virDomainInterfacePtr *ifaces_ret = NULL;

    if (!dom->conn->networkDriver ||
        !dom->conn->networkDriver->networkGetDHCPLeases) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Network driver does not support DHCP lease query"));
        return -1;
    }

    for (i = 0; i < vm->def->nnets; i++) {
        if (vm->def->nets[i]->type != VIR_DOMAIN_NET_TYPE_NETWORK)
            continue;

        virMacAddrFormat(&(vm->def->nets[i]->mac), macaddr);
        virObjectUnref(network);
        network = virNetworkLookupByName(dom->conn,
                                         vm->def->nets[i]->data.network.name);

        if ((n_leases = virNetworkGetDHCPLeases(network, macaddr,
                                                &leases, 0)) < 0)
            goto error;

        if (n_leases) {
            if (VIR_EXPAND_N(ifaces_ret, ifaces_count, 1) < 0)
                goto error;

            if (VIR_ALLOC(ifaces_ret[ifaces_count - 1]) < 0)
                goto error;

            iface = ifaces_ret[ifaces_count - 1];
            /* Assuming each lease corresponds to a separate IP */
            iface->naddrs = n_leases;

            if (VIR_ALLOC_N(iface->addrs, iface->naddrs) < 0)
                goto error;

            if (VIR_STRDUP(iface->name, vm->def->nets[i]->ifname) < 0)
                goto cleanup;

            if (VIR_STRDUP(iface->hwaddr, macaddr) < 0)
                goto cleanup;
        }

        for (j = 0; j < n_leases; j++) {
            virNetworkDHCPLeasePtr lease = leases[j];
            virDomainIPAddressPtr ip_addr = &iface->addrs[j];

            if (VIR_STRDUP(ip_addr->addr, lease->ipaddr) < 0)
                goto cleanup;

            ip_addr->type = lease->type;
            ip_addr->prefix = lease->prefix;
        }

        for (j = 0; j < n_leases; j++)
            virNetworkDHCPLeaseFree(leases[j]);

        VIR_FREE(leases);
    }

    *ifaces = ifaces_ret;
    ifaces_ret = NULL;
    rv = ifaces_count;

 cleanup:
    virObjectUnref(network);
    if (leases) {
        for (i = 0; i < n_leases; i++)
            virNetworkDHCPLeaseFree(leases[i]);
    }
    VIR_FREE(leases);

    return rv;

 error:
    if (ifaces_ret) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces_ret[i]);
    }
    VIR_FREE(ifaces_ret);

    goto cleanup;
}


static int
qemuDomainSetUserPassword(virDomainPtr dom,
                          const char *user,
                          const char *password,
                          unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;
    int rv;

    virCheckFlags(VIR_DOMAIN_PASSWORD_ENCRYPTED, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return ret;

    if (virDomainSetUserPasswordEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!qemuDomainAgentAvailable(vm, true))
        goto endjob;

    qemuDomainObjEnterAgent(vm);
    rv = qemuAgentSetUserPassword(priv->agent, user, password,
                                  flags & VIR_DOMAIN_PASSWORD_ENCRYPTED);
    qemuDomainObjExitAgent(vm);

    if (rv < 0)
        goto endjob;

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int qemuDomainRename(virDomainPtr dom,
                            const char *new_name,
                            unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virQEMUDriverConfigPtr cfg = NULL;
    virDomainObjPtr vm = NULL;
    virDomainObjPtr tmp_dom = NULL;
    virObjectEventPtr event_new = NULL;
    virObjectEventPtr event_old = NULL;
    int ret = -1;
    char *new_dom_name = NULL;
    char *old_dom_name = NULL;
    char *old_dom_cfg_file = NULL;

    virCheckFlags(0, ret);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainRenameEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot rename active domain"));
        goto endjob;
    }

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot rename a transient domain"));
        goto endjob;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain has to be shutoff before renaming"));
        goto endjob;
    }

    if (virDomainSnapshotObjListNum(vm->snapshots, NULL, 0) > 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot rename domain with snapshots"));
        goto endjob;
    }

    if (STREQ(vm->def->name, new_name)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Can't rename domain to itself"));
        goto endjob;
    }

    /*
     * This is a rather racy check, but still better than reporting
     * internal error.  And since new_name != name here, there's no
     * deadlock imminent.
     */
    tmp_dom = virDomainObjListFindByName(driver->domains, new_name);
    if (tmp_dom) {
        virObjectUnlock(tmp_dom);
        virObjectUnref(tmp_dom);
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain with name '%s' already exists"),
                       new_name);
        goto endjob;
    }

    if (VIR_STRDUP(new_dom_name, new_name) < 0)
        goto endjob;

    if (!(old_dom_cfg_file = virDomainConfigFile(cfg->configDir,
                                                 vm->def->name))) {
        goto endjob;
    }

    if (virDomainObjListRenameAddNew(driver->domains, vm, new_name) < 0)
        goto endjob;

    event_old = virDomainEventLifecycleNewFromObj(vm,
                                            VIR_DOMAIN_EVENT_UNDEFINED,
                                            VIR_DOMAIN_EVENT_UNDEFINED_RENAMED);

    /* Switch name in domain definition. */
    old_dom_name = vm->def->name;
    vm->def->name = new_dom_name;
    new_dom_name = NULL;

    if (virDomainSaveConfig(cfg->configDir, vm->def) < 0)
        goto rollback;

    if (virFileExists(old_dom_cfg_file) &&
        unlink(old_dom_cfg_file) < 0) {
        virReportSystemError(errno,
                             _("cannot remove old domain config file %s"),
                             old_dom_cfg_file);
        goto rollback;
    }

    /* Remove old domain name from table. */
    virDomainObjListRenameRemove(driver->domains, old_dom_name);

    event_new = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_DEFINED,
                                              VIR_DOMAIN_EVENT_DEFINED_RENAMED);

    /* Success, domain has been renamed. */
    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    VIR_FREE(old_dom_cfg_file);
    VIR_FREE(old_dom_name);
    VIR_FREE(new_dom_name);
    qemuDomainEventQueue(driver, event_old);
    qemuDomainEventQueue(driver, event_new);
    virObjectUnref(cfg);
    return ret;

 rollback:
    if (old_dom_name) {
        new_dom_name = vm->def->name;
        vm->def->name = old_dom_name;
        old_dom_name = NULL;
    }

    virDomainObjListRenameRemove(driver->domains, new_name);
    goto endjob;
}

static virHypervisorDriver qemuHypervisorDriver = {
    .name = QEMU_DRIVER_NAME,
    .connectOpen = qemuConnectOpen, /* 0.2.0 */
    .connectClose = qemuConnectClose, /* 0.2.0 */
    .connectSupportsFeature = qemuConnectSupportsFeature, /* 0.5.0 */
    .connectGetType = qemuConnectGetType, /* 0.2.0 */
    .connectGetVersion = qemuConnectGetVersion, /* 0.2.0 */
    .connectGetHostname = qemuConnectGetHostname, /* 0.3.3 */
    .connectGetSysinfo = qemuConnectGetSysinfo, /* 0.8.8 */
    .connectGetMaxVcpus = qemuConnectGetMaxVcpus, /* 0.2.1 */
    .nodeGetInfo = qemuNodeGetInfo, /* 0.2.0 */
    .connectGetCapabilities = qemuConnectGetCapabilities, /* 0.2.1 */
    .connectListDomains = qemuConnectListDomains, /* 0.2.0 */
    .connectNumOfDomains = qemuConnectNumOfDomains, /* 0.2.0 */
    .connectListAllDomains = qemuConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = qemuDomainCreateXML, /* 0.2.0 */
    .domainLookupByID = qemuDomainLookupByID, /* 0.2.0 */
    .domainLookupByUUID = qemuDomainLookupByUUID, /* 0.2.0 */
    .domainLookupByName = qemuDomainLookupByName, /* 0.2.0 */
    .domainSuspend = qemuDomainSuspend, /* 0.2.0 */
    .domainResume = qemuDomainResume, /* 0.2.0 */
    .domainShutdown = qemuDomainShutdown, /* 0.2.0 */
    .domainShutdownFlags = qemuDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = qemuDomainReboot, /* 0.9.3 */
    .domainReset = qemuDomainReset, /* 0.9.7 */
    .domainDestroy = qemuDomainDestroy, /* 0.2.0 */
    .domainDestroyFlags = qemuDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = qemuDomainGetOSType, /* 0.2.2 */
    .domainGetMaxMemory = qemuDomainGetMaxMemory, /* 0.4.2 */
    .domainSetMaxMemory = qemuDomainSetMaxMemory, /* 0.4.2 */
    .domainSetMemory = qemuDomainSetMemory, /* 0.4.2 */
    .domainSetMemoryFlags = qemuDomainSetMemoryFlags, /* 0.9.0 */
    .domainSetMemoryParameters = qemuDomainSetMemoryParameters, /* 0.8.5 */
    .domainGetMemoryParameters = qemuDomainGetMemoryParameters, /* 0.8.5 */
    .domainSetMemoryStatsPeriod = qemuDomainSetMemoryStatsPeriod, /* 1.1.1 */
    .domainSetBlkioParameters = qemuDomainSetBlkioParameters, /* 0.9.0 */
    .domainGetBlkioParameters = qemuDomainGetBlkioParameters, /* 0.9.0 */
    .domainGetInfo = qemuDomainGetInfo, /* 0.2.0 */
    .domainGetState = qemuDomainGetState, /* 0.9.2 */
    .domainGetControlInfo = qemuDomainGetControlInfo, /* 0.9.3 */
    .domainSave = qemuDomainSave, /* 0.2.0 */
    .domainSaveFlags = qemuDomainSaveFlags, /* 0.9.4 */
    .domainRestore = qemuDomainRestore, /* 0.2.0 */
    .domainRestoreFlags = qemuDomainRestoreFlags, /* 0.9.4 */
    .domainSaveImageGetXMLDesc = qemuDomainSaveImageGetXMLDesc, /* 0.9.4 */
    .domainSaveImageDefineXML = qemuDomainSaveImageDefineXML, /* 0.9.4 */
    .domainCoreDump = qemuDomainCoreDump, /* 0.7.0 */
    .domainCoreDumpWithFormat = qemuDomainCoreDumpWithFormat, /* 1.2.3 */
    .domainScreenshot = qemuDomainScreenshot, /* 0.9.2 */
    .domainSetVcpus = qemuDomainSetVcpus, /* 0.4.4 */
    .domainSetVcpusFlags = qemuDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = qemuDomainGetVcpusFlags, /* 0.8.5 */
    .domainPinVcpu = qemuDomainPinVcpu, /* 0.4.4 */
    .domainPinVcpuFlags = qemuDomainPinVcpuFlags, /* 0.9.3 */
    .domainGetVcpuPinInfo = qemuDomainGetVcpuPinInfo, /* 0.9.3 */
    .domainPinEmulator = qemuDomainPinEmulator, /* 0.10.0 */
    .domainGetEmulatorPinInfo = qemuDomainGetEmulatorPinInfo, /* 0.10.0 */
    .domainGetVcpus = qemuDomainGetVcpus, /* 0.4.4 */
    .domainGetMaxVcpus = qemuDomainGetMaxVcpus, /* 0.4.4 */
    .domainGetIOThreadInfo = qemuDomainGetIOThreadInfo, /* 1.2.14 */
    .domainPinIOThread = qemuDomainPinIOThread, /* 1.2.14 */
    .domainAddIOThread = qemuDomainAddIOThread, /* 1.2.15 */
    .domainDelIOThread = qemuDomainDelIOThread, /* 1.2.15 */
    .domainGetSecurityLabel = qemuDomainGetSecurityLabel, /* 0.6.1 */
    .domainGetSecurityLabelList = qemuDomainGetSecurityLabelList, /* 0.10.0 */
    .nodeGetSecurityModel = qemuNodeGetSecurityModel, /* 0.6.1 */
    .domainGetXMLDesc = qemuDomainGetXMLDesc, /* 0.2.0 */
    .connectDomainXMLFromNative = qemuConnectDomainXMLFromNative, /* 0.6.4 */
    .connectDomainXMLToNative = qemuConnectDomainXMLToNative, /* 0.6.4 */
    .connectListDefinedDomains = qemuConnectListDefinedDomains, /* 0.2.0 */
    .connectNumOfDefinedDomains = qemuConnectNumOfDefinedDomains, /* 0.2.0 */
    .domainCreate = qemuDomainCreate, /* 0.2.0 */
    .domainCreateWithFlags = qemuDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = qemuDomainDefineXML, /* 0.2.0 */
    .domainDefineXMLFlags = qemuDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = qemuDomainUndefine, /* 0.2.0 */
    .domainUndefineFlags = qemuDomainUndefineFlags, /* 0.9.4 */
    .domainAttachDevice = qemuDomainAttachDevice, /* 0.4.1 */
    .domainAttachDeviceFlags = qemuDomainAttachDeviceFlags, /* 0.7.7 */
    .domainDetachDevice = qemuDomainDetachDevice, /* 0.5.0 */
    .domainDetachDeviceFlags = qemuDomainDetachDeviceFlags, /* 0.7.7 */
    .domainUpdateDeviceFlags = qemuDomainUpdateDeviceFlags, /* 0.8.0 */
    .domainGetAutostart = qemuDomainGetAutostart, /* 0.2.1 */
    .domainSetAutostart = qemuDomainSetAutostart, /* 0.2.1 */
    .domainGetSchedulerType = qemuDomainGetSchedulerType, /* 0.7.0 */
    .domainGetSchedulerParameters = qemuDomainGetSchedulerParameters, /* 0.7.0 */
    .domainGetSchedulerParametersFlags = qemuDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = qemuDomainSetSchedulerParameters, /* 0.7.0 */
    .domainSetSchedulerParametersFlags = qemuDomainSetSchedulerParametersFlags, /* 0.9.2 */
    .domainMigratePerform = qemuDomainMigratePerform, /* 0.5.0 */
    .domainBlockResize = qemuDomainBlockResize, /* 0.9.8 */
    .domainBlockStats = qemuDomainBlockStats, /* 0.4.1 */
    .domainBlockStatsFlags = qemuDomainBlockStatsFlags, /* 0.9.5 */
    .domainInterfaceStats = qemuDomainInterfaceStats, /* 0.4.1 */
    .domainMemoryStats = qemuDomainMemoryStats, /* 0.7.5 */
    .domainBlockPeek = qemuDomainBlockPeek, /* 0.4.4 */
    .domainMemoryPeek = qemuDomainMemoryPeek, /* 0.4.4 */
    .domainGetBlockInfo = qemuDomainGetBlockInfo, /* 0.8.1 */
    .nodeGetCPUStats = qemuNodeGetCPUStats, /* 0.9.3 */
    .nodeGetMemoryStats = qemuNodeGetMemoryStats, /* 0.9.3 */
    .nodeGetCellsFreeMemory = qemuNodeGetCellsFreeMemory, /* 0.4.4 */
    .nodeGetFreeMemory = qemuNodeGetFreeMemory, /* 0.4.4 */
    .connectDomainEventRegister = qemuConnectDomainEventRegister, /* 0.5.0 */
    .connectDomainEventDeregister = qemuConnectDomainEventDeregister, /* 0.5.0 */
    .domainMigratePrepare2 = qemuDomainMigratePrepare2, /* 0.5.0 */
    .domainMigrateFinish2 = qemuDomainMigrateFinish2, /* 0.5.0 */
    .nodeDeviceDettach = qemuNodeDeviceDettach, /* 0.6.1 */
    .nodeDeviceDetachFlags = qemuNodeDeviceDetachFlags, /* 1.0.5 */
    .nodeDeviceReAttach = qemuNodeDeviceReAttach, /* 0.6.1 */
    .nodeDeviceReset = qemuNodeDeviceReset, /* 0.6.1 */
    .domainMigratePrepareTunnel = qemuDomainMigratePrepareTunnel, /* 0.7.2 */
    .connectIsEncrypted = qemuConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = qemuConnectIsSecure, /* 0.7.3 */
    .domainIsActive = qemuDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = qemuDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = qemuDomainIsUpdated, /* 0.8.6 */
    .connectCompareCPU = qemuConnectCompareCPU, /* 0.7.5 */
    .connectBaselineCPU = qemuConnectBaselineCPU, /* 0.7.7 */
    .domainGetJobInfo = qemuDomainGetJobInfo, /* 0.7.7 */
    .domainGetJobStats = qemuDomainGetJobStats, /* 1.0.3 */
    .domainAbortJob = qemuDomainAbortJob, /* 0.7.7 */
    .domainMigrateSetMaxDowntime = qemuDomainMigrateSetMaxDowntime, /* 0.8.0 */
    .domainMigrateGetCompressionCache = qemuDomainMigrateGetCompressionCache, /* 1.0.3 */
    .domainMigrateSetCompressionCache = qemuDomainMigrateSetCompressionCache, /* 1.0.3 */
    .domainMigrateSetMaxSpeed = qemuDomainMigrateSetMaxSpeed, /* 0.9.0 */
    .domainMigrateGetMaxSpeed = qemuDomainMigrateGetMaxSpeed, /* 0.9.5 */
    .connectDomainEventRegisterAny = qemuConnectDomainEventRegisterAny, /* 0.8.0 */
    .connectDomainEventDeregisterAny = qemuConnectDomainEventDeregisterAny, /* 0.8.0 */
    .domainManagedSave = qemuDomainManagedSave, /* 0.8.0 */
    .domainHasManagedSaveImage = qemuDomainHasManagedSaveImage, /* 0.8.0 */
    .domainManagedSaveRemove = qemuDomainManagedSaveRemove, /* 0.8.0 */
    .domainSnapshotCreateXML = qemuDomainSnapshotCreateXML, /* 0.8.0 */
    .domainSnapshotGetXMLDesc = qemuDomainSnapshotGetXMLDesc, /* 0.8.0 */
    .domainSnapshotNum = qemuDomainSnapshotNum, /* 0.8.0 */
    .domainSnapshotListNames = qemuDomainSnapshotListNames, /* 0.8.0 */
    .domainListAllSnapshots = qemuDomainListAllSnapshots, /* 0.9.13 */
    .domainSnapshotNumChildren = qemuDomainSnapshotNumChildren, /* 0.9.7 */
    .domainSnapshotListChildrenNames = qemuDomainSnapshotListChildrenNames, /* 0.9.7 */
    .domainSnapshotListAllChildren = qemuDomainSnapshotListAllChildren, /* 0.9.13 */
    .domainSnapshotLookupByName = qemuDomainSnapshotLookupByName, /* 0.8.0 */
    .domainHasCurrentSnapshot = qemuDomainHasCurrentSnapshot, /* 0.8.0 */
    .domainSnapshotGetParent = qemuDomainSnapshotGetParent, /* 0.9.7 */
    .domainSnapshotCurrent = qemuDomainSnapshotCurrent, /* 0.8.0 */
    .domainSnapshotIsCurrent = qemuDomainSnapshotIsCurrent, /* 0.9.13 */
    .domainSnapshotHasMetadata = qemuDomainSnapshotHasMetadata, /* 0.9.13 */
    .domainRevertToSnapshot = qemuDomainRevertToSnapshot, /* 0.8.0 */
    .domainSnapshotDelete = qemuDomainSnapshotDelete, /* 0.8.0 */
    .domainQemuMonitorCommand = qemuDomainQemuMonitorCommand, /* 0.8.3 */
    .domainQemuAttach = qemuDomainQemuAttach, /* 0.9.4 */
    .domainQemuAgentCommand = qemuDomainQemuAgentCommand, /* 0.10.0 */
    .connectDomainQemuMonitorEventRegister = qemuConnectDomainQemuMonitorEventRegister, /* 1.2.3 */
    .connectDomainQemuMonitorEventDeregister = qemuConnectDomainQemuMonitorEventDeregister, /* 1.2.3 */
    .domainOpenConsole = qemuDomainOpenConsole, /* 0.8.6 */
    .domainOpenGraphics = qemuDomainOpenGraphics, /* 0.9.7 */
    .domainOpenGraphicsFD = qemuDomainOpenGraphicsFD, /* 1.2.8 */
    .domainInjectNMI = qemuDomainInjectNMI, /* 0.9.2 */
    .domainMigrateBegin3 = qemuDomainMigrateBegin3, /* 0.9.2 */
    .domainMigratePrepare3 = qemuDomainMigratePrepare3, /* 0.9.2 */
    .domainMigratePrepareTunnel3 = qemuDomainMigratePrepareTunnel3, /* 0.9.2 */
    .domainMigratePerform3 = qemuDomainMigratePerform3, /* 0.9.2 */
    .domainMigrateFinish3 = qemuDomainMigrateFinish3, /* 0.9.2 */
    .domainMigrateConfirm3 = qemuDomainMigrateConfirm3, /* 0.9.2 */
    .domainSendKey = qemuDomainSendKey, /* 0.9.4 */
    .domainBlockJobAbort = qemuDomainBlockJobAbort, /* 0.9.4 */
    .domainGetBlockJobInfo = qemuDomainGetBlockJobInfo, /* 0.9.4 */
    .domainBlockJobSetSpeed = qemuDomainBlockJobSetSpeed, /* 0.9.4 */
    .domainBlockPull = qemuDomainBlockPull, /* 0.9.4 */
    .domainBlockRebase = qemuDomainBlockRebase, /* 0.9.10 */
    .domainBlockCopy = qemuDomainBlockCopy, /* 1.2.9 */
    .domainBlockCommit = qemuDomainBlockCommit, /* 1.0.0 */
    .connectIsAlive = qemuConnectIsAlive, /* 0.9.8 */
    .nodeSuspendForDuration = qemuNodeSuspendForDuration, /* 0.9.8 */
    .domainSetBlockIoTune = qemuDomainSetBlockIoTune, /* 0.9.8 */
    .domainGetBlockIoTune = qemuDomainGetBlockIoTune, /* 0.9.8 */
    .domainSetNumaParameters = qemuDomainSetNumaParameters, /* 0.9.9 */
    .domainGetNumaParameters = qemuDomainGetNumaParameters, /* 0.9.9 */
    .domainGetInterfaceParameters = qemuDomainGetInterfaceParameters, /* 0.9.9 */
    .domainSetInterfaceParameters = qemuDomainSetInterfaceParameters, /* 0.9.9 */
    .domainGetDiskErrors = qemuDomainGetDiskErrors, /* 0.9.10 */
    .domainSetMetadata = qemuDomainSetMetadata, /* 0.9.10 */
    .domainGetMetadata = qemuDomainGetMetadata, /* 0.9.10 */
    .domainPMSuspendForDuration = qemuDomainPMSuspendForDuration, /* 0.9.11 */
    .domainPMWakeup = qemuDomainPMWakeup, /* 0.9.11 */
    .domainGetCPUStats = qemuDomainGetCPUStats, /* 0.9.11 */
    .nodeGetMemoryParameters = qemuNodeGetMemoryParameters, /* 0.10.2 */
    .nodeSetMemoryParameters = qemuNodeSetMemoryParameters, /* 0.10.2 */
    .nodeGetCPUMap = qemuNodeGetCPUMap, /* 1.0.0 */
    .domainFSTrim = qemuDomainFSTrim, /* 1.0.1 */
    .domainOpenChannel = qemuDomainOpenChannel, /* 1.0.2 */
    .domainMigrateBegin3Params = qemuDomainMigrateBegin3Params, /* 1.1.0 */
    .domainMigratePrepare3Params = qemuDomainMigratePrepare3Params, /* 1.1.0 */
    .domainMigratePrepareTunnel3Params = qemuDomainMigratePrepareTunnel3Params, /* 1.1.0 */
    .domainMigratePerform3Params = qemuDomainMigratePerform3Params, /* 1.1.0 */
    .domainMigrateFinish3Params = qemuDomainMigrateFinish3Params, /* 1.1.0 */
    .domainMigrateConfirm3Params = qemuDomainMigrateConfirm3Params, /* 1.1.0 */
    .connectGetCPUModelNames = qemuConnectGetCPUModelNames, /* 1.1.3 */
    .domainFSFreeze = qemuDomainFSFreeze, /* 1.2.5 */
    .domainFSThaw = qemuDomainFSThaw, /* 1.2.5 */
    .domainGetTime = qemuDomainGetTime, /* 1.2.5 */
    .domainSetTime = qemuDomainSetTime, /* 1.2.5 */
    .nodeGetFreePages = qemuNodeGetFreePages, /* 1.2.6 */
    .connectGetDomainCapabilities = qemuConnectGetDomainCapabilities, /* 1.2.7 */
    .connectGetAllDomainStats = qemuConnectGetAllDomainStats, /* 1.2.8 */
    .nodeAllocPages = qemuNodeAllocPages, /* 1.2.9 */
    .domainGetFSInfo = qemuDomainGetFSInfo, /* 1.2.11 */
    .domainInterfaceAddresses = qemuDomainInterfaceAddresses, /* 1.2.14 */
    .domainSetUserPassword = qemuDomainSetUserPassword, /* 1.2.16 */
    .domainRename = qemuDomainRename, /* 1.2.19 */
};


static virConnectDriver qemuConnectDriver = {
    .hypervisorDriver = &qemuHypervisorDriver,
};

static virStateDriver qemuStateDriver = {
    .name = QEMU_DRIVER_NAME,
    .stateInitialize = qemuStateInitialize,
    .stateAutoStart = qemuStateAutoStart,
    .stateCleanup = qemuStateCleanup,
    .stateReload = qemuStateReload,
    .stateStop = qemuStateStop,
};

int qemuRegister(void)
{
    if (virRegisterConnectDriver(&qemuConnectDriver,
                                 true) < 0)
        return -1;
    if (virRegisterStateDriver(&qemuStateDriver) < 0)
        return -1;
    return 0;
}
