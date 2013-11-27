/*
 * qemu_driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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
#include "qemu_bridge_filter.h"
#include "qemu_process.h"
#include "qemu_migration.h"

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "nodeinfo.h"
#include "virstatslinux.h"
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

#define VIR_FROM_THIS VIR_FROM_QEMU

#define QEMU_DRIVER_NAME "QEMU"

#define QEMU_NB_MEM_PARAM  3

#define QEMU_NB_BLOCK_IO_TUNE_PARAM  6

#define QEMU_NB_NUMA_PARAM 2

#define QEMU_NB_TOTAL_CPU_STAT_PARAM 3
#define QEMU_NB_PER_CPU_STAT_PARAM 2

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

#define QEMU_NB_BLKIO_PARAM  2

#define QEMU_NB_BANDWIDTH_PARAM 6

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
                              unsigned int flags);

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


virQEMUDriverPtr qemu_driver = NULL;


static void
qemuVMDriverLock(void) {}
static void
qemuVMDriverUnlock(void) {}

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
 * This function looks up @domain and returns the appropriate
 * virDomainObjPtr.
 *
 * Returns the domain object which is locked on success, NULL
 * otherwise.
 */
static virDomainObjPtr
qemuDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    virQEMUDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

/* Looks up the domain object from snapshot and unlocks the driver. The
 * returned domain object is locked and the caller is responsible for
 * unlocking it */
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
    virResetLastError();
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        if (qemuDomainObjBeginJob(data->driver, vm,
                                  QEMU_JOB_MODIFY) < 0) {
            err = virGetLastError();
            VIR_ERROR(_("Failed to start job on VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : _("unknown error"));
            goto cleanup;
        }

        if (qemuDomainObjStart(data->conn, data->driver, vm, flags) < 0) {
            err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : _("unknown error"));
        }

        if (!qemuDomainObjEndJob(data->driver, vm))
            vm = NULL;
    }

    ret = 0;
cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    if (conn)
        virConnectClose(conn);
    virObjectUnref(cfg);
}

static int
qemuSecurityInit(virQEMUDriverPtr driver)
{
    char **names;
    virSecurityManagerPtr mgr = NULL;
    virSecurityManagerPtr stack = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (cfg->securityDriverNames &&
        cfg->securityDriverNames[0]) {
        names = cfg->securityDriverNames;
        while (names && *names) {
            if (!(mgr = virSecurityManagerNew(*names,
                                              QEMU_DRIVER_NAME,
                                              cfg->allowDiskFormatProbing,
                                              cfg->securityDefaultConfined,
                                              cfg->securityRequireConfined)))
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
                                          cfg->allowDiskFormatProbing,
                                          cfg->securityDefaultConfined,
                                          cfg->securityRequireConfined)))
            goto error;
        if (!(stack = virSecurityManagerNewStack(mgr)))
            goto error;
        mgr = NULL;
    }

    if (cfg->privileged) {
        if (!(mgr = virSecurityManagerNewDAC(QEMU_DRIVER_NAME,
                                             cfg->user,
                                             cfg->group,
                                             cfg->allowDiskFormatProbing,
                                             cfg->securityDefaultConfined,
                                             cfg->securityRequireConfined,
                                             cfg->dynamicOwnership)))
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

    while ((entry = readdir(dir))) {
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
                                              QEMU_EXPECTED_VIRT_TYPES,
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

    if (vm->def->id >= *driver_maxid)
        *driver_maxid = vm->def->id + 1;

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
    char *membase = NULL;
    char *mempath = NULL;
    virQEMUDriverConfigPtr cfg;
    uid_t run_uid = -1;
    gid_t run_gid = -1;

    if (VIR_ALLOC(qemu_driver) < 0)
        return -1;

    if (virMutexInit(&qemu_driver->lock) < 0) {
        VIR_ERROR(_("cannot initialize mutex"));
        VIR_FREE(qemu_driver);
        return -1;
    }

    qemu_driver->inhibitCallback = callback;
    qemu_driver->inhibitOpaque = opaque;

    /* Don't have a dom0 so start from 1 */
    qemu_driver->nextvmid = 1;

    if (!(qemu_driver->domains = virDomainObjListNew()))
        goto error;

    /* Init domain events */
    qemu_driver->domainEventState = virDomainEventStateNew();
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

        if ((errno = networkDisableAllFrames(qemu_driver))) {
            virReportSystemError(errno,
                                 _("failed to add rule to drop all frames in '%s'"),
                                 __FILE__);
            goto error;
        }
   }

    /* Allocate bitmap for remote display port reservations. We cannot
     * do this before the config is loaded properly, since the port
     * numbers are configurable now */
    if ((qemu_driver->remotePorts =
         virPortAllocatorNew(_("display"),
                             cfg->remotePortMin,
                             cfg->remotePortMax)) == NULL)
        goto error;

    if ((qemu_driver->webSocketPorts =
         virPortAllocatorNew(_("webSocket"),
                             cfg->webSocketPortMin,
                             cfg->webSocketPortMax)) == NULL)
        goto error;

    if ((qemu_driver->migrationPorts =
         virPortAllocatorNew(_("migration"),
                             cfg->migrationPortMin,
                             cfg->migrationPortMax)) == NULL)
        goto error;

    if (qemuSecurityInit(qemu_driver) < 0)
        goto error;

    if ((qemu_driver->activePciHostdevs = virPCIDeviceListNew()) == NULL)
        goto error;

    if ((qemu_driver->activeUsbHostdevs = virUSBDeviceListNew()) == NULL)
        goto error;

    if ((qemu_driver->inactivePciHostdevs = virPCIDeviceListNew()) == NULL)
        goto error;

    if ((qemu_driver->activeScsiHostdevs = virSCSIDeviceListNew()) == NULL)
        goto error;

    if (!(qemu_driver->sharedDevices = virHashCreate(30, qemuSharedDeviceEntryFree)))
        goto error;

    if (privileged) {
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
        run_uid = cfg->user;
        run_gid = cfg->group;
    }

    qemu_driver->qemuCapsCache = virQEMUCapsCacheNew(cfg->libDir,
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
     * will let our spawned QEMU instances use it.
     *
     * NB the check for '/', since user may config "" to disable hugepages
     * even when mounted
     */
    if (cfg->hugetlbfsMount &&
        cfg->hugetlbfsMount[0] == '/') {
        if (virAsprintf(&membase, "%s/libvirt",
                        cfg->hugetlbfsMount) < 0 ||
            virAsprintf(&mempath, "%s/qemu", membase) < 0)
            goto error;

        if (virFileMakePath(mempath) < 0) {
            virReportSystemError(errno,
                                 _("unable to create hugepage path %s"), mempath);
            goto error;
        }
        if (cfg->privileged) {
            if (virFileUpdatePerm(membase, 0, S_IXGRP | S_IXOTH) < 0)
                goto error;
            if (chown(mempath, cfg->user, cfg->group) < 0) {
                virReportSystemError(errno,
                                     _("unable to set ownership on %s to %d:%d"),
                                     mempath, (int) cfg->user,
                                     (int) cfg->group);
                goto error;
            }
        }
        VIR_FREE(membase);

        cfg->hugepagePath = mempath;
    }

    if (!(qemu_driver->closeCallbacks = virCloseCallbacksNew()))
        goto error;

    /* Get all the running persistent or transient configs first */
    if (virDomainObjListLoadAllConfigs(qemu_driver->domains,
                                       cfg->stateDir,
                                       NULL, 1,
                                       qemu_driver->caps,
                                       qemu_driver->xmlopt,
                                       QEMU_EXPECTED_VIRT_TYPES,
                                       NULL, NULL) < 0)
        goto error;

    /* find the maximum ID from active and transient configs to initialize
     * the driver with. This is to avoid race between autostart and reconnect
     * threads */
    virDomainObjListForEach(qemu_driver->domains,
                            qemuDomainFindMaxID,
                            &qemu_driver->nextvmid);

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
                                       QEMU_EXPECTED_VIRT_TYPES,
                                       NULL, NULL) < 0)
        goto error;

    qemuProcessReconnectAll(conn, qemu_driver);

    virDomainObjListForEach(qemu_driver->domains,
                            qemuDomainSnapshotLoad,
                            cfg->snapshotDir);

    virDomainObjListForEach(qemu_driver->domains,
                            qemuDomainManagedSaveLoad,
                            qemu_driver);

    qemu_driver->workerPool = virThreadPoolNew(0, 1, 0, qemuProcessEventHandler, qemu_driver);
    if (!qemu_driver->workerPool)
        goto error;

    if (conn)
        virConnectClose(conn);

    virNWFilterRegisterCallbackDriver(&qemuCallbackDriver);
    return 0;

error:
    if (conn)
        virConnectClose(conn);
    VIR_FREE(driverConf);
    VIR_FREE(membase);
    VIR_FREE(mempath);
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
        virDomainEventPtr event =
            virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
        if (event)
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
qemuStateReload(void) {
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
                                   QEMU_EXPECTED_VIRT_TYPES,
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
qemuStateStop(void) {
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
            if (state == VIR_DOMAIN_PAUSED) {
                flags[i] = VIR_DOMAIN_SAVE_PAUSED;
            }
        }
        virDomainSuspend(domains[i]);
    }

    ret = 0;
    /* Then we save the VMs to disk */
    for (i = 0; i < numDomains; i++)
        if (virDomainManagedSave(domains[i], flags[i]) < 0)
            ret = -1;

 cleanup:
    for (i = 0; i < numDomains; i++)
        virDomainFree(domains[i]);
    VIR_FREE(domains);
    VIR_FREE(flags);
    if (conn)
        virConnectClose(conn);
    virObjectUnref(cfg);

    return ret;
}

/**
 * qemuStateCleanup:
 *
 * Shutdown the QEmu daemon, it will stop all active domains and networks
 */
static int
qemuStateCleanup(void) {
    if (!qemu_driver)
        return -1;

    virNWFilterUnRegisterCallbackDriver(&qemuCallbackDriver);
    virObjectUnref(qemu_driver->config);
    virObjectUnref(qemu_driver->activePciHostdevs);
    virObjectUnref(qemu_driver->inactivePciHostdevs);
    virObjectUnref(qemu_driver->activeUsbHostdevs);
    virObjectUnref(qemu_driver->activeScsiHostdevs);
    virHashFree(qemu_driver->sharedDevices);
    virObjectUnref(qemu_driver->caps);
    virQEMUCapsCacheFree(qemu_driver->qemuCapsCache);

    virObjectUnref(qemu_driver->domains);
    virObjectUnref(qemu_driver->remotePorts);
    virObjectUnref(qemu_driver->webSocketPorts);
    virObjectUnref(qemu_driver->migrationPorts);

    virObjectUnref(qemu_driver->xmlopt);

    virSysinfoDefFree(qemu_driver->hostsysinfo);

    virObjectUnref(qemu_driver->closeCallbacks);

    VIR_FREE(qemu_driver->qemuImgBinary);

    virObjectUnref(qemu_driver->securityManager);

    ebtablesContextFree(qemu_driver->ebtables);

    /* Free domain callback list */
    virDomainEventStateFree(qemu_driver->domainEventState);

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

        if (cfg->privileged) {
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
kvmGetMaxVCPUs(void) {
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
    if (virBufferError(&buf)) {
        virReportOOMError();
        return NULL;
    }
    return virBufferContentAndReset(&buf);
}

static int qemuConnectGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED, const char *type) {
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

    if ((xml = virCapabilitiesFormatXML(caps)) == NULL)
        virReportOOMError();
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
    unsigned long long usertime, systime;
    long rss;
    int cpu;
    int ret;

    /* In general, we cannot assume pid_t fits in int; but /proc parsing
     * is specific to Linux where int works fine.  */
    if (tid)
        ret = virAsprintf(&proc, "/proc/%d/task/%d/stat", (int) pid, tid);
    else
        ret = virAsprintf(&proc, "/proc/%d/stat", (int) pid);
    if (ret < 0)
        return -1;

    if (!(pidinfo = fopen(proc, "r"))) {
        /* VM probably shut down, so fake 0 */
        if (cpuTime)
            *cpuTime = 0;
        if (lastCpu)
            *lastCpu = 0;
        if (vm_rss)
            *vm_rss = 0;
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
               "%*d %*d %*d %*d %*d %*d %*u %*u %ld %*u %*u %*u"
               /* startstack -> processor */
               "%*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %d",
               &usertime, &systime, &rss, &cpu) != 4) {
        VIR_FORCE_FCLOSE(pidinfo);
        VIR_WARN("cannot parse process status data");
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

    /* We got pages
     * We want kiloBytes
     * _SC_PAGESIZE is page size in Bytes
     * So calculate, but first lower the pagesize so we don't get overflow */
    if (vm_rss)
        *vm_rss = rss * (sysconf(_SC_PAGESIZE) >> 10);


    VIR_DEBUG("Got status for %d/%d user=%llu sys=%llu cpu=%d rss=%ld",
              (int) pid, tid, usertime, systime, cpu, rss);

    VIR_FORCE_FCLOSE(pidinfo);

    return 0;
}


static virDomainPtr qemuDomainLookupByID(virConnectPtr conn,
                                         int id) {
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
                                           const unsigned char *uuid) {
    virQEMUDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(driver->domains, uuid);

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
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr qemuDomainLookupByName(virConnectPtr conn,
                                           const char *name) {
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
    if (vm)
        virObjectUnlock(vm);
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
    if (obj)
        virObjectUnlock(obj);
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
    if (obj)
        virObjectUnlock(obj);
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
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int qemuConnectGetVersion(virConnectPtr conn, unsigned long *version) {
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


static int qemuConnectListDomains(virConnectPtr conn, int *ids, int nids) {
    virQEMUDriverPtr driver = conn->privateData;
    int n;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     virConnectListDomainsCheckACL, conn);

    return n;
}

static int qemuConnectNumOfDomains(virConnectPtr conn) {
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
                                        unsigned int flags) {
    virQEMUDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    virDomainEventPtr event2 = NULL;
    unsigned int start_flags = VIR_QEMU_PROCESS_START_COLD;
    virQEMUCapsPtr qemuCaps = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY, NULL);

    if (flags & VIR_DOMAIN_START_PAUSED)
        start_flags |= VIR_QEMU_PROCESS_START_PAUSED;
    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_QEMU_PROCESS_START_AUTODESTROY;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
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
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    def = NULL;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0) {
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
        goto cleanup;
    }

    if (qemuProcessStart(conn, driver, vm, NULL, -1, NULL, NULL,
                         VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                         start_flags) < 0) {
        virDomainAuditStart(vm, "booted", false);
        if (qemuDomainObjEndJob(driver, vm))
            qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    if (event && (flags & VIR_DOMAIN_START_PAUSED)) {
        /* There are two classes of event-watching clients - those
         * that only care about on/off (and must see a started event
         * no matter what, but don't care about suspend events), and
         * those that also care about running/paused.  To satisfy both
         * client types, we have to send two events.  */
        event2 = virDomainEventNewFromObj(vm,
                                          VIR_DOMAIN_EVENT_SUSPENDED,
                                          VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }
    virDomainAuditStart(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virObjectUnlock(vm);
    if (event) {
        qemuDomainEventQueue(driver, event);
        if (event2)
            qemuDomainEventQueue(driver, event2);
    }
    virObjectUnref(caps);
    virObjectUnref(qemuCaps);
    return dom;
}


static int qemuDomainSuspend(virDomainPtr dom) {
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;
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
        if (qemuProcessStopCPUs(driver, vm, reason, QEMU_ASYNC_JOB_NONE) < 0) {
            goto endjob;
        }

        if (eventDetail >= 0) {
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_SUSPENDED,
                                             eventDetail);
        }
    }
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;
    ret = 0;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);

    if (event)
        qemuDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}


static int qemuDomainResume(virDomainPtr dom) {
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;
    int state;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

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
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }
    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto endjob;
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;
    ret = 0;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static int qemuDomainShutdownFlags(virDomainPtr dom, unsigned int flags) {
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    bool useAgent = false, agentRequested, acpiRequested;
    bool isReboot = false;
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

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (priv->agentError) {
        if (agentRequested && !acpiRequested) {
            virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                           _("QEMU guest agent is not "
                             "available due to an error"));
            goto cleanup;
        } else {
            useAgent = false;
        }
    }

    if (!priv->agent) {
        if (agentRequested && !acpiRequested) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("QEMU guest agent is not configured"));
            goto cleanup;
        } else {
            useAgent = false;
        }
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

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
        qemuDomainSetFakeReboot(driver, vm, isReboot);

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSystemPowerdown(priv->mon);
        qemuDomainObjExitMonitor(driver, vm);
    }

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    bool useAgent = false;
    bool isReboot = true;
    int agentFlag = QEMU_AGENT_SHUTDOWN_REBOOT;

    virCheckFlags(VIR_DOMAIN_REBOOT_ACPI_POWER_BTN |
                  VIR_DOMAIN_REBOOT_GUEST_AGENT, -1);

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_REBOOT_ACPI_POWER_BTN) &&
        (flags & VIR_DOMAIN_REBOOT_GUEST_AGENT)) {
        virReportInvalidArg(flags, "%s",
                            _("flags for acpi power button and guest agent are mutually exclusive"));
        return -1;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_DESTROY ||
        vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_PRESERVE) {
        agentFlag = QEMU_AGENT_SHUTDOWN_POWERDOWN;
        isReboot = false;
        VIR_INFO("Domain on_reboot setting overridden, shutting down");
    }

    priv = vm->privateData;

    if (virDomainRebootEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((flags & VIR_DOMAIN_REBOOT_GUEST_AGENT) ||
        (!(flags & VIR_DOMAIN_REBOOT_ACPI_POWER_BTN) &&
         priv->agent))
        useAgent = true;

    if (useAgent) {
        if (priv->agentError) {
            virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                           _("QEMU guest agent is not "
                             "available due to an error"));
            goto cleanup;
        }
        if (!priv->agent) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("QEMU guest agent is not configured"));
            goto cleanup;
        }
    } else {
#if WITH_YAJL
        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MONITOR_JSON)) {
            if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NO_SHUTDOWN)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Reboot is not supported with this QEMU binary"));
                goto cleanup;
            }
        } else {
#endif
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Reboot is not supported without the JSON monitor"));
            goto cleanup;
#if WITH_YAJL
        }
#endif
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (useAgent) {
        qemuDomainObjEnterAgent(vm);
        ret = qemuAgentShutdown(priv->agent, agentFlag);
        qemuDomainObjExitAgent(vm);
    } else {
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSystemPowerdown(priv->mon);
        qemuDomainObjExitMonitor(driver, vm);

        if (ret == 0)
            qemuDomainSetFakeReboot(driver, vm, isReboot);
    }

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    qemuDomainObjExitMonitor(driver, vm);

    priv->fakeReboot = false;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_DESTROY_GRACEFUL, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    qemuDomainSetFakeReboot(driver, vm, false);


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

    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED, 0);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    virDomainAuditStop(vm, "destroyed");

    if (!vm->persistent) {
        if (qemuDomainObjEndJob(driver, vm))
            qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }
    ret = 0;

endjob:
    if (vm && !qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
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

    ignore_value(VIR_STRDUP(type, vm->def->os.type));

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    ret = vm->def->mem.max_balloon;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int qemuDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                                    unsigned int flags) {
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1, r;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

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

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto endjob;
    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        /* resize the maximum memory */

        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot resize the maximum memory on an "
                             "active domain"));
            goto endjob;
        }

        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            /* Help clang 2.8 decipher the logic flow.  */
            sa_assert(persistentDef);
            persistentDef->mem.max_balloon = newmem;
            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(cfg->configDir, persistentDef);
            goto endjob;
        }

    } else {
        /* resize the current memory */

        if (newmem > vm->def->mem.max_balloon) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("cannot set memory higher than max memory"));
            goto endjob;
        }

        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            priv = vm->privateData;
            qemuDomainObjEnterMonitor(driver, vm);
            r = qemuMonitorSetBalloon(priv->mon, newmem);
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditMemory(vm, vm->def->mem.cur_balloon, newmem, "update",
                                 r == 1);
            if (r < 0)
                goto endjob;

            /* Lack of balloon support is a fatal error */
            if (r == 0) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("Unable to change memory of active domain without "
                                 "the balloon device and guest OS balloon driver"));
                goto endjob;
            }
        }

        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            sa_assert(persistentDef);
            persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(cfg->configDir, persistentDef);
            goto endjob;
        }
    }

    ret = 0;
endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
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
    virDomainDefPtr persistentDef = NULL;
    int ret = -1, r;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetMemoryStatsPeriodEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto endjob;
    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;

    /* Set the balloon driver collection interval */
    priv = vm->privateData;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {

        qemuDomainObjEnterMonitor(driver, vm);
        r = qemuMonitorSetMemoryStatsPeriod(priv->mon, period);
        qemuDomainObjExitMonitor(driver, vm);
        if (r < 0)
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("unable to set balloon driver collection period"));
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        sa_assert(persistentDef);
        persistentDef->memballoon->period = period;
        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        goto endjob;
    }

    ret = 0;
endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
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
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int qemuDomainGetInfo(virDomainPtr dom,
                             virDomainInfoPtr info)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    int err;
    unsigned long long balloon;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    info->state = virDomainObjGetState(vm, NULL);

    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (qemuGetProcessInfo(&(info->cpuTime), NULL, NULL, vm->pid, 0) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("cannot read cputime for domain"));
            goto cleanup;
        }
    }

    info->maxMem = vm->def->mem.max_balloon;

    if (virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;

        if ((vm->def->memballoon != NULL) &&
            (vm->def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_NONE)) {
            info->memory = vm->def->mem.max_balloon;
        } else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BALLOON_EVENT)) {
            info->memory = vm->def->mem.cur_balloon;
        } else if (qemuDomainJobAllowed(priv, QEMU_JOB_QUERY)) {
            if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
                goto cleanup;
            if (!virDomainObjIsActive(vm))
                err = 0;
            else {
                qemuDomainObjEnterMonitor(driver, vm);
                err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
                qemuDomainObjExitMonitor(driver, vm);
            }
            if (!qemuDomainObjEndJob(driver, vm)) {
                vm = NULL;
                goto cleanup;
            }

            if (err < 0) {
                /* We couldn't get current memory allocation but that's not
                 * a show stopper; we wouldn't get it if there was a job
                 * active either
                 */
                info->memory = vm->def->mem.cur_balloon;
            } else if (err == 0) {
                /* Balloon not supported, so maxmem is always the allocation */
                info->memory = vm->def->mem.max_balloon;
            } else {
                info->memory = balloon;
            }
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
        virObjectUnlock(vm);
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
    if (vm)
        virObjectUnlock(vm);
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

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    memset(info, 0, sizeof(*info));

    if (priv->monError) {
        info->state = VIR_DOMAIN_CONTROL_ERROR;
    } else if (priv->job.active) {
        if (!priv->monStart) {
            info->state = VIR_DOMAIN_CONTROL_JOB;
            if (virTimeMillisNow(&info->stateTime) < 0)
                goto cleanup;
            info->stateTime -= priv->job.start;
        } else {
            info->state = VIR_DOMAIN_CONTROL_OCCUPIED;
            if (virTimeMillisNow(&info->stateTime) < 0)
                goto cleanup;
            info->stateTime -= priv->monStart;
        }
    } else {
        info->state = VIR_DOMAIN_CONTROL_OK;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
bswap_header(virQEMUSaveHeaderPtr hdr) {
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
    int path_shared = virStorageFileIsSharedFS(path);
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
            is_reg = !!S_ISREG(sb.st_mode);
            /* If the path is regular file which exists
             * already and dynamic_ownership is off, we don't
             * want to change it's ownership, just open it as-is */
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

            /* Retry creating the file as qemu user */

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
                     enum qemuDomainAsyncJob asyncJob)
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
     * slightly larger XML, so we add a miminum padding prior to
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

    if (ret != 0 && needUnlink)
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
    int rc;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!qemuMigrationIsAllowed(driver, vm, vm->def, false, false))
        goto cleanup;

    if (qemuDomainObjBeginAsyncJob(driver, vm, QEMU_ASYNC_JOB_SAVE) < 0)
        goto cleanup;

    memset(&priv->job.info, 0, sizeof(priv->job.info));
    priv->job.info.type = VIR_DOMAIN_JOB_UNBOUNDED;

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
                                            QEMU_EXPECTED_VIRT_TYPES,
                                            VIR_DOMAIN_XML_INACTIVE))) {
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

    /* Shut it down */
    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SAVED, 0);
    virDomainAuditStop(vm, "saved");
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SAVED);
    if (!vm->persistent) {
        if (qemuDomainObjEndAsyncJob(driver, vm) > 0)
            qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }

endjob:
    if (vm) {
        if (ret != 0) {
            if (was_running && virDomainObjIsActive(vm)) {
                rc = qemuProcessStartCPUs(driver, vm, dom->conn,
                                          VIR_DOMAIN_RUNNING_SAVE_CANCELED,
                                          QEMU_ASYNC_JOB_SAVE);
                if (rc < 0) {
                    VIR_WARN("Unable to resume guest CPUs after save failure");
                    event = virDomainEventNewFromObj(vm,
                                                     VIR_DOMAIN_EVENT_SUSPENDED,
                                                     VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
                }
            }
        }
        if (qemuDomainObjEndAsyncJob(driver, vm) == 0)
            vm = NULL;
    }

cleanup:
    VIR_FREE(xml);
    if (event)
        qemuDomainEventQueue(driver, event);
    if (vm)
        virObjectUnlock(vm);
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
                  VIR_DOMAIN_SAVE_PAUSED, -1);

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
    vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    if ((ret = qemuDomainSaveInternal(driver, dom, vm, name, compressed,
                                      NULL, flags)) == 0)
        vm->hasManagedSave = true;

    vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    virObjectUnlock(vm);
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
    virObjectUnlock(vm);
    return ret;
}

static int qemuDumpToFd(virQEMUDriverPtr driver, virDomainObjPtr vm,
                        int fd, enum qemuDomainAsyncJob asyncJob)
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

    priv->job.dump_memory_only = true;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorDumpToFd(priv->mon, fd);
    qemuDomainObjExitMonitor(driver, vm);

    return ret;
}

static int
doCoreDump(virQEMUDriverPtr driver,
           virDomainObjPtr vm,
           const char *path,
           virQEMUSaveFormat compress,
           unsigned int dump_flags)
{
    int fd = -1;
    int ret = -1;
    virFileWrapperFdPtr wrapperFd = NULL;
    int directFlag = 0;
    unsigned int flags = VIR_FILE_WRAPPER_NON_BLOCKING;

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
        ret = qemuDumpToFd(driver, vm, fd, QEMU_ASYNC_JOB_DUMP);
    } else {
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

static int qemuDomainCoreDump(virDomainPtr dom,
                              const char *path,
                              unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    bool resume = false, paused = false;
    int ret = -1;
    virDomainEventPtr event = NULL;

    virCheckFlags(VIR_DUMP_LIVE | VIR_DUMP_CRASH |
                  VIR_DUMP_BYPASS_CACHE | VIR_DUMP_RESET |
                  VIR_DUMP_MEMORY_ONLY, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainCoreDumpEnsureACL(dom->conn, vm->def) < 0)
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

    ret = doCoreDump(driver, vm, path, getCompressionType(driver), flags);
    if (ret < 0)
        goto endjob;

    paused = true;

endjob:
    if ((ret == 0) && (flags & VIR_DUMP_CRASH)) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_CRASHED, 0);
        virDomainAuditStop(vm, "crashed");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    }

    /* Since the monitor is always attached to a pty for libvirt, it
       will support synchronous operations so we always get here after
       the migration is complete.  */
    else if (((resume && paused) || (flags & VIR_DUMP_RESET)) &&
             virDomainObjIsActive(vm)) {
        if ((ret == 0) && (flags & VIR_DUMP_RESET)) {
            priv =  vm->privateData;
            qemuDomainObjEnterMonitor(driver, vm);
            ret = qemuMonitorSystemReset(priv->mon);
            qemuDomainObjExitMonitor(driver, vm);
        }

        if (resume && qemuProcessStartCPUs(driver, vm, dom->conn,
                                           VIR_DOMAIN_RUNNING_UNPAUSED,
                                           QEMU_ASYNC_JOB_DUMP) < 0) {
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_SUSPENDED,
                                             VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
            if (virGetLastError() == NULL)
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("resuming after dump failed"));
        }
    }

    if (qemuDomainObjEndAsyncJob(driver, vm) == 0)
        vm = NULL;
    else if ((ret == 0) && (flags & VIR_DUMP_CRASH) && !vm->persistent) {
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    return ret;
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
        qemuDomainObjExitMonitor(driver, vm);
        goto endjob;
    }
    qemuDomainObjExitMonitor(driver, vm);

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

    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
                             getCompressionType(driver), flags);
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
    /* Safe to ignore value since ref count was incremented in
     * qemuProcessHandleWatchdog().
     */
    ignore_value(qemuDomainObjEndAsyncJob(driver, vm));

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
                     getCompressionType(driver), flags);
    if (ret < 0)
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("Dump failed"));

endjob:
    /* Safe to ignore value since ref count was incremented in
     * qemuProcessHandleGuestPanic().
     */
    ignore_value(qemuDomainObjEndAsyncJob(driver, vm));

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
    virDomainEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Ignoring GUEST_PANICKED event from inactive domain %s",
                  vm->def->name);
        goto cleanup;
    }

    virDomainObjSetState(vm,
                         VIR_DOMAIN_CRASHED,
                         VIR_DOMAIN_CRASHED_PANICKED);

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_CRASHED,
                                     VIR_DOMAIN_EVENT_CRASHED_PANICKED);

    if (event)
        qemuDomainEventQueue(driver, event);

    if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
        VIR_WARN("Unable to release lease on %s", vm->def->name);
    VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
        VIR_WARN("Unable to save status on vm %s after state change",
                 vm->def->name);
     }

    switch (action) {
    case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_DESTROY:
        if (doCoreDumpToAutoDumpPath(driver, vm, VIR_DUMP_MEMORY_ONLY) < 0) {
            goto cleanup;
        }
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
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);

        if (event)
            qemuDomainEventQueue(driver, event);

        virDomainAuditStop(vm, "destroyed");

        if (!vm->persistent) {
            qemuDomainRemoveInactive(driver, vm);
        }
        break;

    case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_RESTART:
        if (doCoreDumpToAutoDumpPath(driver, vm, VIR_DUMP_MEMORY_ONLY) < 0) {
            goto cleanup;
        }
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
    virObjectUnref(cfg);
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
    default:
       break;
    }

    if (virObjectUnref(vm))
        virObjectUnlock(vm);
    VIR_FREE(processEvent);
}

static int qemuDomainHotplugVcpus(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  unsigned int nvcpus)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;
    int rc = 1;
    int ret = -1;
    int oldvcpus = vm->def->vcpus;
    int vcpus = oldvcpus;
    pid_t *cpupids = NULL;
    int ncpupids;
    virCgroupPtr cgroup_vcpu = NULL;

    qemuDomainObjEnterMonitor(driver, vm);

    /* We need different branches here, because we want to offline
     * in reverse order to onlining, so any partial fail leaves us in a
     * reasonably sensible state */
    if (nvcpus > vcpus) {
        for (i = vcpus; i < nvcpus; i++) {
            /* Online new CPU */
            rc = qemuMonitorSetCPU(priv->mon, i, true);
            if (rc == 0)
                goto unsupported;
            if (rc < 0)
                goto cleanup;

            vcpus++;
        }
    } else {
        for (i = vcpus - 1; i >= nvcpus; i--) {
            /* Offline old CPU */
            rc = qemuMonitorSetCPU(priv->mon, i, false);
            if (rc == 0)
                goto unsupported;
            if (rc < 0)
                goto cleanup;

            vcpus--;
        }
    }

    /* hotplug succeeded */

    ret = 0;

    /* After hotplugging the CPUs we need to re-detect threads corresponding
     * to the virtual CPUs. Some older versions don't provide the thread ID
     * or don't have the "info cpus" command (and they don't support multiple
     * CPUs anyways), so errors in the re-detection will not be treated
     * fatal */
    if ((ncpupids = qemuMonitorGetCPUInfo(priv->mon, &cpupids)) <= 0) {
        virResetLastError();
        goto cleanup;
    }

    /* check if hotplug has failed */
    if (vcpus < oldvcpus && ncpupids == oldvcpus) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("qemu didn't unplug the vCPUs properly"));
        vcpus = oldvcpus;
        ret = -1;
        goto cleanup;
    }

    if (ncpupids != vcpus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("got wrong number of vCPU pids from QEMU monitor. "
                         "got %d, wanted %d"),
                       ncpupids, vcpus);
        vcpus = oldvcpus;
        ret = -1;
        goto cleanup;
    }

    if (nvcpus > oldvcpus) {
        for (i = oldvcpus; i < nvcpus; i++) {
            if (priv->cgroup) {
                int rv = -1;
                /* Create cgroup for the onlined vcpu */
                if (virCgroupNewVcpu(priv->cgroup, i, true, &cgroup_vcpu) < 0)
                    goto cleanup;

                /* Add vcpu thread to the cgroup */
                rv = virCgroupAddTask(cgroup_vcpu, cpupids[i]);
                if (rv < 0) {
                    virReportSystemError(-rv,
                                         _("unable to add vcpu %zu task %d to cgroup"),
                                         i, cpupids[i]);
                    virCgroupRemove(cgroup_vcpu);
                    goto cleanup;
                }
            }

            /* Inherit def->cpuset */
            if (vm->def->cpumask) {
                /* vm->def->cputune.vcpupin can't be NULL if
                 * vm->def->cpumask is not NULL.
                 */
                virDomainVcpuPinDefPtr vcpupin = NULL;

                if (VIR_REALLOC_N(vm->def->cputune.vcpupin,
                                  vm->def->cputune.nvcpupin + 1) < 0)
                    goto cleanup;

                if (VIR_ALLOC(vcpupin) < 0)
                    goto cleanup;

                vcpupin->cpumask = virBitmapNew(VIR_DOMAIN_CPUMASK_LEN);
                virBitmapCopy(vcpupin->cpumask, vm->def->cpumask);
                vcpupin->vcpuid = i;
                vm->def->cputune.vcpupin[vm->def->cputune.nvcpupin++] = vcpupin;

                if (cgroup_vcpu) {
                    if (qemuSetupCgroupVcpuPin(cgroup_vcpu,
                                               vm->def->cputune.vcpupin,
                                               vm->def->cputune.nvcpupin, i) < 0) {
                        virReportError(VIR_ERR_OPERATION_INVALID,
                                       _("failed to set cpuset.cpus in cgroup"
                                         " for vcpu %zu"), i);
                        ret = -1;
                        goto cleanup;
                    }
                } else {
                    if (virProcessSetAffinity(cpupids[i],
                                              vcpupin->cpumask) < 0) {
                        virReportError(VIR_ERR_SYSTEM_ERROR,
                                       _("failed to set cpu affinity for vcpu %zu"),
                                       i);
                        ret = -1;
                        goto cleanup;
                    }
                }
            }

            virCgroupFree(&cgroup_vcpu);
        }
    } else {
        for (i = oldvcpus - 1; i >= nvcpus; i--) {
            virDomainVcpuPinDefPtr vcpupin = NULL;

            if (priv->cgroup) {
                if (virCgroupNewVcpu(priv->cgroup, i, false, &cgroup_vcpu) < 0)
                    goto cleanup;

                /* Remove cgroup for the offlined vcpu */
                virCgroupRemove(cgroup_vcpu);
                virCgroupFree(&cgroup_vcpu);
            }

            /* Free vcpupin setting */
            if ((vcpupin = virDomainLookupVcpuPin(vm->def, i))) {
                VIR_FREE(vcpupin);
            }
        }
    }

    priv->nvcpupids = ncpupids;
    VIR_FREE(priv->vcpupids);
    priv->vcpupids = cpupids;
    cpupids = NULL;

cleanup:
    qemuDomainObjExitMonitor(driver, vm);
    vm->def->vcpus = vcpus;
    VIR_FREE(cpupids);
    virDomainAuditVcpu(vm, oldvcpus, nvcpus, "update", rc == 1);
    if (cgroup_vcpu)
        virCgroupFree(&cgroup_vcpu);
    return ret;

unsupported:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("cannot change vcpu count of this domain"));
    goto cleanup;
}


static int
qemuDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                        unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef;
    int ret = -1;
    bool maximum;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    qemuAgentCPUInfoPtr cpuinfo = NULL;
    int ncpuinfo;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM |
                  VIR_DOMAIN_VCPU_GUEST, -1);

    if (!nvcpus || (unsigned short) nvcpus != nvcpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("argument out of range: %d"), nvcpus);
        return -1;
    }

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    maximum = (flags & VIR_DOMAIN_VCPU_MAXIMUM) != 0;
    flags &= ~VIR_DOMAIN_VCPU_MAXIMUM;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;

    /* MAXIMUM cannot be mixed with LIVE.  */
    if (maximum && (flags & VIR_DOMAIN_AFFECT_LIVE)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("cannot adjust maximum on running domain"));
        goto endjob;
    }

    if (!maximum && nvcpus > vm->def->maxvcpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable"
                         " vcpus for the domain: %d > %d"),
                       nvcpus, vm->def->maxvcpus);
        goto endjob;
    }

    if (flags & VIR_DOMAIN_VCPU_GUEST) {
        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("changing of maximum vCPU count isn't supported "
                             "via guest agent"));
            goto endjob;
        }

        if (priv->agentError) {
            virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                           _("QEMU guest agent is not "
                             "available due to an error"));
            goto endjob;
        }

        if (!priv->agent) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("QEMU guest agent is not configured"));
            goto endjob;
        }

        qemuDomainObjEnterAgent(vm);
        ncpuinfo = qemuAgentGetVCPUs(priv->agent, &cpuinfo);
        qemuDomainObjExitAgent(vm);

        if (ncpuinfo < 0)
            goto endjob;

        if (qemuAgentUpdateCPUInfo(nvcpus, cpuinfo, ncpuinfo) < 0)
            goto endjob;

        qemuDomainObjEnterAgent(vm);
        ret = qemuAgentSetVCPUs(priv->agent, cpuinfo, ncpuinfo);
        qemuDomainObjExitAgent(vm);

        if (ret < 0)
            goto endjob;

        if (ret < ncpuinfo) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to set state of cpu %d via guest agent"),
                           cpuinfo[ret-1].id);
            ret = -1;
            goto endjob;
        }
    } else {
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            if (qemuDomainHotplugVcpus(driver, vm, nvcpus) < 0)
                goto endjob;
        }

        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            if (maximum) {
                persistentDef->maxvcpus = nvcpus;
                if (nvcpus < persistentDef->vcpus)
                    persistentDef->vcpus = nvcpus;
            } else {
                persistentDef->vcpus = nvcpus;
            }

            if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
                goto endjob;
        }
    }

    ret = 0;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    VIR_FREE(cpuinfo);
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
                       unsigned int flags) {

    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    virCgroupPtr cgroup_vcpu = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    bool doReset = false;
    int newVcpuPinNum = 0;
    virDomainVcpuPinDefPtr *newVcpuPin = NULL;
    virBitmapPtr pcpumap = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinVcpuFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (vcpu > (priv->nvcpupids-1)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("vcpu number out of range %d > %d"),
                       vcpu, priv->nvcpupids);
        goto cleanup;
    }

    pcpumap = virBitmapNewData(cpumap, maplen);
    if (!pcpumap)
        goto cleanup;

    if (virBitmapIsAllClear(pcpumap)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Empty cpu list for pinning"));
        goto cleanup;
    }

    /* pinning to all physical cpus means resetting,
     * so check if we can reset setting.
     */
    if (virBitmapIsAllSet(pcpumap))
        doReset = true;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {

        if (priv->vcpupids == NULL) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cpu affinity is not supported"));
            goto cleanup;
        }

        if (vm->def->cputune.vcpupin) {
            newVcpuPin = virDomainVcpuPinDefCopy(vm->def->cputune.vcpupin,
                                                 vm->def->cputune.nvcpupin);
            if (!newVcpuPin)
                goto cleanup;

            newVcpuPinNum = vm->def->cputune.nvcpupin;
        } else {
            if (VIR_ALLOC(newVcpuPin) < 0)
                goto cleanup;
            newVcpuPinNum = 0;
        }

        if (virDomainVcpuPinAdd(&newVcpuPin, &newVcpuPinNum, cpumap, maplen, vcpu) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to update vcpupin"));
            virDomainVcpuPinDefArrayFree(newVcpuPin, newVcpuPinNum);
            goto cleanup;
        }

        /* Configure the corresponding cpuset cgroup before set affinity. */
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (virCgroupNewVcpu(priv->cgroup, vcpu, false, &cgroup_vcpu) < 0)
                goto cleanup;
            if (qemuSetupCgroupVcpuPin(cgroup_vcpu, newVcpuPin, newVcpuPinNum, vcpu) < 0) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("failed to set cpuset.cpus in cgroup"
                                 " for vcpu %d"), vcpu);
                goto cleanup;
            }
        } else {
            if (virProcessSetAffinity(priv->vcpupids[vcpu], pcpumap) < 0) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("failed to set cpu affinity for vcpu %d"),
                               vcpu);
                goto cleanup;
            }
        }

        if (doReset) {
            if (virDomainVcpuPinDel(vm->def, vcpu) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to delete vcpupin xml of "
                                 "a running domain"));
                goto cleanup;
            }
        } else {
            if (vm->def->cputune.vcpupin)
                virDomainVcpuPinDefArrayFree(vm->def->cputune.vcpupin, vm->def->cputune.nvcpupin);

            vm->def->cputune.vcpupin = newVcpuPin;
            vm->def->cputune.nvcpupin = newVcpuPinNum;
            newVcpuPin = NULL;
        }

        if (newVcpuPin)
            virDomainVcpuPinDefArrayFree(newVcpuPin, newVcpuPinNum);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {

        if (doReset) {
            if (virDomainVcpuPinDel(persistentDef, vcpu) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to delete vcpupin xml of "
                                 "a persistent domain"));
                goto cleanup;
            }
        } else {
            if (!persistentDef->cputune.vcpupin) {
                if (VIR_ALLOC(persistentDef->cputune.vcpupin) < 0)
                    goto cleanup;
                persistentDef->cputune.nvcpupin = 0;
            }
            if (virDomainVcpuPinAdd(&persistentDef->cputune.vcpupin,
                                    &persistentDef->cputune.nvcpupin,
                                    cpumap,
                                    maplen,
                                    vcpu) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to update or add vcpupin xml of "
                                 "a persistent domain"));
                goto cleanup;
            }
        }

        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (cgroup_vcpu)
        virCgroupFree(&cgroup_vcpu);
    if (vm)
        virObjectUnlock(vm);
    virBitmapFree(pcpumap);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainPinVcpu(virDomainPtr dom,
                   unsigned int vcpu,
                   unsigned char *cpumap,
                   int maplen) {
    return qemuDomainPinVcpuFlags(dom, vcpu, cpumap, maplen,
                                  VIR_DOMAIN_AFFECT_LIVE);
}

static int
qemuDomainGetVcpuPinInfo(virDomainPtr dom,
                         int ncpumaps,
                         unsigned char *cpumaps,
                         int maplen,
                         unsigned int flags) {

    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr targetDef = NULL;
    int ret = -1;
    int maxcpu, hostcpus, vcpu, pcpu;
    int n;
    virDomainVcpuPinDefPtr *vcpupin_list;
    virBitmapPtr cpumask = NULL;
    unsigned char *cpumap;
    bool pinned;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpuPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &targetDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        targetDef = vm->def;
    }

    /* Coverity didn't realize that targetDef must be set if we got here.  */
    sa_assert(targetDef);

    if ((hostcpus = nodeGetCPUCount()) < 0)
        goto cleanup;

    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    /* Clamp to actual number of vcpus */
    if (ncpumaps > targetDef->vcpus)
        ncpumaps = targetDef->vcpus;

    if (ncpumaps < 1) {
        goto cleanup;
    }

    /* initialize cpumaps */
    memset(cpumaps, 0xff, maplen * ncpumaps);
    if (maxcpu % 8) {
        for (vcpu = 0; vcpu < ncpumaps; vcpu++) {
            cpumap = VIR_GET_CPUMAP(cpumaps, maplen, vcpu);
            cpumap[maplen - 1] &= (1 << maxcpu % 8) - 1;
        }
    }

    /* if vcpupin setting exists, there are unused physical cpus */
    for (n = 0; n < targetDef->cputune.nvcpupin; n++) {
        vcpupin_list = targetDef->cputune.vcpupin;
        vcpu = vcpupin_list[n]->vcpuid;
        cpumask = vcpupin_list[n]->cpumask;
        cpumap = VIR_GET_CPUMAP(cpumaps, maplen, vcpu);
        for (pcpu = 0; pcpu < maxcpu; pcpu++) {
            if (virBitmapGetBit(cpumask, pcpu, &pinned) < 0)
                goto cleanup;
            if (!pinned)
                VIR_UNUSE_CPU(cpumap, pcpu);
        }
    }
    ret = ncpumaps;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
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
    pid_t pid;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    bool doReset = false;
    int newVcpuPinNum = 0;
    virDomainVcpuPinDefPtr *newVcpuPin = NULL;
    virBitmapPtr pcpumap = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinEmulatorEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Changing affinity for emulator thread dynamically "
                         "is not allowed when CPU placement is 'auto'"));
        goto cleanup;
    }

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    priv = vm->privateData;

    pcpumap = virBitmapNewData(cpumap, maplen);
    if (!pcpumap)
        goto cleanup;

    if (virBitmapIsAllClear(pcpumap)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Empty cpu list for pinning"));
        goto cleanup;
    }

    /* pinning to all physical cpus means resetting,
     * so check if we can reset setting.
     */
    if (virBitmapIsAllSet(pcpumap))
        doReset = true;

    pid = vm->pid;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {

        if (priv->vcpupids != NULL) {
            if (VIR_ALLOC(newVcpuPin) < 0)
                goto cleanup;

            if (virDomainVcpuPinAdd(&newVcpuPin, &newVcpuPinNum, cpumap, maplen, -1) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to update vcpupin"));
                virDomainVcpuPinDefArrayFree(newVcpuPin, newVcpuPinNum);
                goto cleanup;
            }

            if (virCgroupHasController(priv->cgroup,
                                       VIR_CGROUP_CONTROLLER_CPUSET)) {
                /*
                 * Configure the corresponding cpuset cgroup.
                 */
                if (virCgroupNewEmulator(priv->cgroup, false, &cgroup_emulator) < 0)
                    goto cleanup;
                if (qemuSetupCgroupEmulatorPin(cgroup_emulator,
                                               newVcpuPin[0]->cpumask) < 0) {
                    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                   _("failed to set cpuset.cpus in cgroup"
                                     " for emulator threads"));
                    goto cleanup;
                }
            } else {
                if (virProcessSetAffinity(pid, pcpumap) < 0) {
                    virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                                   _("failed to set cpu affinity for "
                                     "emulator threads"));
                    goto cleanup;
                }
            }

            if (doReset) {
                if (virDomainEmulatorPinDel(vm->def) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("failed to delete emulatorpin xml of "
                                     "a running domain"));
                    goto cleanup;
                }
            } else {
                virDomainVcpuPinDefFree(vm->def->cputune.emulatorpin);
                vm->def->cputune.emulatorpin = newVcpuPin[0];
                VIR_FREE(newVcpuPin);
            }

            if (newVcpuPin)
                virDomainVcpuPinDefArrayFree(newVcpuPin, newVcpuPinNum);
        } else {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cpu affinity is not supported"));
            goto cleanup;
        }

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {

        if (doReset) {
            if (virDomainEmulatorPinDel(persistentDef) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to delete emulatorpin xml of "
                                 "a persistent domain"));
                goto cleanup;
            }
        } else {
            if (virDomainEmulatorPinAdd(persistentDef, cpumap, maplen) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to update or add emulatorpin xml "
                                 "of a persistent domain"));
                goto cleanup;
            }
        }

        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (cgroup_emulator)
        virCgroupFree(&cgroup_emulator);
    virBitmapFree(pcpumap);
    virObjectUnref(caps);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetEmulatorPinInfo(virDomainPtr dom,
                             unsigned char *cpumaps,
                             int maplen,
                             unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr targetDef = NULL;
    int ret = -1;
    int maxcpu, hostcpus, pcpu;
    virBitmapPtr cpumask = NULL;
    bool pinned;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetEmulatorPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt,
                                        vm, &flags, &targetDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE)
        targetDef = vm->def;

    /* Coverity didn't realize that targetDef must be set if we got here. */
    sa_assert(targetDef);

    if ((hostcpus = nodeGetCPUCount()) < 0)
        goto cleanup;

    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    /* initialize cpumaps */
    memset(cpumaps, 0xff, maplen);
    if (maxcpu % 8) {
        cpumaps[maplen - 1] &= (1 << maxcpu % 8) - 1;
    }

    if (targetDef->cputune.emulatorpin) {
        cpumask = targetDef->cputune.emulatorpin->cpumask;
    } else if (targetDef->cpumask) {
        cpumask = targetDef->cpumask;
    } else {
        ret = 0;
        goto cleanup;
    }

    for (pcpu = 0; pcpu < maxcpu; pcpu++) {
        if (virBitmapGetBit(cpumask, pcpu, &pinned) < 0)
            goto cleanup;
        if (!pinned)
            VIR_UNUSE_CPU(cpumaps, pcpu);
    }

    ret = 1;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    return ret;
}

static int
qemuDomainGetVcpus(virDomainPtr dom,
                   virVcpuInfoPtr info,
                   int maxinfo,
                   unsigned char *cpumaps,
                   int maplen) {
    virDomainObjPtr vm;
    size_t i;
    int v, maxcpu, hostcpus;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

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

    priv = vm->privateData;

    if ((hostcpus = nodeGetCPUCount()) < 0)
        goto cleanup;

    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    /* Clamp to actual number of vcpus */
    if (maxinfo > priv->nvcpupids)
        maxinfo = priv->nvcpupids;

    if (maxinfo >= 1) {
        if (info != NULL) {
            memset(info, 0, sizeof(*info) * maxinfo);
            for (i = 0; i < maxinfo; i++) {
                info[i].number = i;
                info[i].state = VIR_VCPU_RUNNING;

                if (priv->vcpupids != NULL &&
                    qemuGetProcessInfo(&(info[i].cpuTime),
                                       &(info[i].cpu),
                                       NULL,
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
                for (v = 0; v < maxinfo; v++) {
                    unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, v);
                    virBitmapPtr map = NULL;
                    unsigned char *tmpmap = NULL;
                    int tmpmapLen = 0;

                    if (virProcessGetAffinity(priv->vcpupids[v],
                                              &map, maxcpu) < 0)
                        goto cleanup;
                    virBitmapToData(map, &tmpmap, &tmpmapLen);
                    if (tmpmapLen > maplen)
                        tmpmapLen = maplen;
                    memcpy(cpumap, tmpmap, tmpmapLen);

                    VIR_FREE(tmpmap);
                    virBitmapFree(map);
                }
            } else {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               "%s", _("cpu affinity is not available"));
                goto cleanup;
            }
        }
    }
    ret = maxinfo;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    virCapsPtr caps = NULL;
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

    if (virDomainGetVcpusFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt,
                                        vm, &flags, &def) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE)
        def = vm->def;

    if (flags & VIR_DOMAIN_VCPU_GUEST) {
        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("vCPU count provided by the guest agent can only be "
                             " requested for live domains"));
            goto cleanup;
        }

        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
            goto cleanup;

        if (priv->agentError) {
            virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                           _("QEMU guest agent is not "
                             "available due to an error"));
            goto endjob;
        }

        if (!priv->agent) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("QEMU guest agent is not configured"));
            goto endjob;
        }

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain is not running"));
            goto endjob;
        }

        qemuDomainObjEnterAgent(vm);
        ncpuinfo = qemuAgentGetVCPUs(priv->agent, &cpuinfo);
        qemuDomainObjExitAgent(vm);

endjob:
        if (!qemuDomainObjEndJob(driver, vm))
            vm = NULL;

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
            ret = def->maxvcpus;
        else
            ret = def->vcpus;
    }


cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    VIR_FREE(cpuinfo);
    return ret;
}

static int
qemuDomainGetMaxVcpus(virDomainPtr dom)
{
    return qemuDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                         VIR_DOMAIN_VCPU_MAXIMUM));
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
    if (vm)
        virObjectUnlock(vm);
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
    if (vm)
        virObjectUnlock(vm);
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

/* Return -1 on most failures after raising error, -2 if edit was specified
 * but xmlin and state (-1 for no change, 0 for paused, 1 for running) do
 * not represent any changes (no error raised), -3 if corrupt image was
 * unlinked (no error raised), and opened fd on success.  */
static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
qemuDomainSaveImageOpen(virQEMUDriverPtr driver,
                        const char *path,
                        virDomainDefPtr *ret_def,
                        virQEMUSaveHeaderPtr ret_header,
                        bool bypass_cache,
                        virFileWrapperFdPtr *wrapperFd,
                        const char *xmlin, int state, bool edit,
                        bool unlink_corrupt)
{
    int fd = -1;
    virQEMUSaveHeader header;
    char *xml = NULL;
    virDomainDefPtr def = NULL;
    int oflags = edit ? O_RDWR : O_RDONLY;
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

    if (edit && STREQ(xml, xmlin) &&
        (state < 0 || state == header.was_running)) {
        VIR_FREE(xml);
        if (VIR_CLOSE(fd) < 0) {
            virReportSystemError(errno, _("cannot close file: %s"), path);
            goto error;
        }
        return -2;
    }
    if (state >= 0)
        header.was_running = state;

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto error;
    if (xmlin) {
        virDomainDefPtr def2 = NULL;
        virDomainDefPtr newdef = NULL;

        if (!(def2 = virDomainDefParseString(xmlin, caps, driver->xmlopt,
                                             QEMU_EXPECTED_VIRT_TYPES,
                                             VIR_DOMAIN_XML_INACTIVE)))
            goto error;

        newdef = qemuDomainDefCopy(driver, def2, VIR_DOMAIN_XML_MIGRATABLE);
        if (!newdef) {
            virDomainDefFree(def2);
            goto error;
        }

        if (!virDomainDefCheckABIStability(def, newdef)) {
            virDomainDefFree(newdef);
            virResetLastError();

            /* Due to a bug in older version of external snapshot creation
             * code, the XML saved in the save image was not a migratable
             * XML. To ensure backwards compatibility with the change of the
             * saved XML type, we need to check the ABI compatibility against
             * the user provided XML if the check against the migratable XML
             * fails. Snapshots created prior to v1.1.3 have this issue. */
            if (!virDomainDefCheckABIStability(def, def2)) {
                virDomainDefFree(def2);
                goto error;
            }

            /* use the user provided XML */
            newdef = def2;
            def2 = NULL;
        } else {
            virDomainDefFree(def2);
        }

        virDomainDefFree(def);
        def = newdef;
    }

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
                           bool start_paused)
{
    int ret = -1;
    virDomainEventPtr event;
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
    ret = qemuProcessStart(conn, driver, vm, "stdio", *fd, path, NULL,
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

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    virDomainAuditStart(vm, "restored", true);
    if (event)
        qemuDomainEventQueue(driver, event);


    /* If it was running before, resume it now unless caller requested pause. */
    if (header->was_running && !start_paused) {
        if (qemuProcessStartCPUs(driver, vm, conn,
                                 VIR_DOMAIN_RUNNING_RESTORED,
                                 QEMU_ASYNC_JOB_NONE) < 0) {
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
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         detail);
        if (event)
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
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int fd = -1;
    int ret = -1;
    virQEMUSaveHeader header;
    virFileWrapperFdPtr wrapperFd = NULL;
    int state = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE |
                  VIR_DOMAIN_SAVE_RUNNING |
                  VIR_DOMAIN_SAVE_PAUSED, -1);


    if (flags & VIR_DOMAIN_SAVE_RUNNING)
        state = 1;
    else if (flags & VIR_DOMAIN_SAVE_PAUSED)
        state = 0;

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header,
                                 (flags & VIR_DOMAIN_SAVE_BYPASS_CACHE) != 0,
                                 &wrapperFd, dxml, state, false, false);
    if (fd < 0)
        goto cleanup;

    if (virDomainRestoreFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    def = NULL;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    ret = qemuDomainSaveImageStartVM(conn, driver, vm, &fd, &header, path,
                                     false);
    if (virFileWrapperFdClose(wrapperFd) < 0)
        VIR_WARN("Failed to close %s", path);

    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;
    else if (ret < 0 && !vm->persistent) {
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }

cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    virFileWrapperFdFree(wrapperFd);
    if (vm)
        virObjectUnlock(vm);
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

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, false, NULL,
                                 NULL, -1, false, false);

    if (fd < 0)
        goto cleanup;

    if (virDomainSaveImageGetXMLDescEnsureACL(conn, def) < 0)
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

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, false, NULL,
                                 dxml, state, true, false);

    if (fd < 0) {
        /* Check for special case of no change needed.  */
        if (fd == -2)
            ret = 0;
        goto cleanup;
    }

    if (virDomainSaveImageDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    xml = qemuDomainDefFormatXML(driver, def,
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
                     bool bypass_cache)
{
    virDomainDefPtr def = NULL;
    int fd = -1;
    int ret = -1;
    virQEMUSaveHeader header;
    virFileWrapperFdPtr wrapperFd = NULL;

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header,
                                 bypass_cache, &wrapperFd, NULL, -1, false,
                                 true);
    if (fd < 0) {
        if (fd == -3)
            ret = 1;
        goto cleanup;
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
                                     start_paused);
    if (virFileWrapperFdClose(wrapperFd) < 0)
        VIR_WARN("Failed to close %s", path);

cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    virFileWrapperFdFree(wrapperFd);
    return ret;
}


static char *qemuDomainGetXMLDesc(virDomainPtr dom,
                                  unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;
    unsigned long long balloon;
    int err = 0;
    qemuDomainObjPrivatePtr priv;

    /* Flags checked by virDomainDefFormat */

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    /* Refresh current memory based on balloon info if supported */
    if ((vm->def->memballoon != NULL) &&
        (vm->def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_NONE) &&
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BALLOON_EVENT) &&
        (virDomainObjIsActive(vm))) {
        /* Don't delay if someone's using the monitor, just use
         * existing most recent data instead */
        if (qemuDomainJobAllowed(priv, QEMU_JOB_QUERY)) {
            if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
                goto cleanup;

            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               "%s", _("domain is not running"));
                goto endjob;
            }

            qemuDomainObjEnterMonitor(driver, vm);
            err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
            qemuDomainObjExitMonitor(driver, vm);

endjob:
            if (!qemuDomainObjEndJob(driver, vm)) {
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

    if ((flags & VIR_DOMAIN_XML_MIGRATABLE))
        flags |= QEMU_DOMAIN_FORMAT_LIVE_FLAGS;

    ret = qemuDomainFormatXML(driver, vm, flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
                                  QEMU_EXPECTED_VIRT_TYPES, 0);
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
                if (VIR_STRDUP(brnamecopy, brname) < 0)
                    goto cleanup;

                virDomainActualNetDefFree(net->data.network.actual);

                memset(net, 0, sizeof(*net));

                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                net->script = NULL;
                net->data.ethernet.dev = brnamecopy;
                net->data.ethernet.ipaddr = NULL;
            } else {
                /* actualType is either NETWORK or DIRECT. In either
                 * case, the best we can do is NULL everything out.
                 */
                virDomainActualNetDefFree(net->data.network.actual);
                memset(net, 0, sizeof(*net));

                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                net->script = NULL;
                net->data.ethernet.dev = NULL;
                net->data.ethernet.ipaddr = NULL;
            }
        } else if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            VIR_FREE(net->data.direct.linkdev);

            memset(net, 0, sizeof(*net));

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            net->script = NULL;
            net->data.ethernet.dev = NULL;
            net->data.ethernet.ipaddr = NULL;
        } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            char *script = net->script;
            char *brname = net->data.bridge.brname;
            char *ipaddr = net->data.bridge.ipaddr;

            memset(net, 0, sizeof(*net));

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            net->script = script;
            net->data.ethernet.dev = brname;
            net->data.ethernet.ipaddr = ipaddr;
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
            size_t j;
            bool needTLSPort = false;
            bool needPort = false;
            int defaultMode = graphics->data.spice.defaultMode;

            if (graphics->data.spice.autoport) {
                /* check if tlsPort or port need allocation */
                for (j = 0; j < VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST; j++) {
                    switch (graphics->data.spice.channels[j]) {
                    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
                        needTLSPort = true;
                        break;

                    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
                        needPort = true;
                        break;

                    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
                        switch (defaultMode) {
                        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
                            needTLSPort = true;
                            break;

                        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
                            needPort = true;
                            break;

                        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
                            needTLSPort = true;
                            needPort = true;
                            break;
                        }
                        break;
                    }
                }
            }

            if (needPort || graphics->data.spice.port == -1)
                graphics->data.spice.port = 5901;

            if (needTLSPort || graphics->data.spice.tlsPort == -1)
                graphics->data.spice.tlsPort = 5902;
        }
    }

    if (!(cmd = qemuBuildCommandLine(conn, driver, def,
                                     &monConfig, monitor_json, qemuCaps,
                                     NULL, -1, NULL, VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,
                                     &buildCommandLineCallbacks)))
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

static int qemuConnectNumOfDefinedDomains(virConnectPtr conn) {
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
                   unsigned int flags)
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
                                       start_paused, bypass_cache);

            if (ret == 0) {
                if (unlink(managed_save) < 0)
                    VIR_WARN("Failed to remove the managed state %s", managed_save);
                else
                    vm->hasManagedSave = false;
            }

            if (ret > 0) {
                VIR_WARN("Ignoring incomplete managed state %s", managed_save);
            } else {
                VIR_WARN("Unable to restore from managed state %s. "
                         "Maybe the file is corrupted?", managed_save);
                goto cleanup;
            }
        }
    }

    ret = qemuProcessStart(conn, driver, vm, NULL, -1, NULL, NULL,
                           VIR_NETDEV_VPORT_PROFILE_OP_CREATE, start_flags);
    virDomainAuditStart(vm, "booted", ret >= 0);
    if (ret >= 0) {
        virDomainEventPtr event =
            virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
        if (event) {
            qemuDomainEventQueue(driver, event);
            if (start_paused) {
                event = virDomainEventNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_SUSPENDED,
                                                 VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
                if (event)
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

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is already running"));
        goto endjob;
    }

    if (qemuDomainObjStart(dom->conn, driver, vm, flags) < 0)
        goto endjob;

    ret = 0;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
qemuDomainCreate(virDomainPtr dom)
{
    return qemuDomainCreateWithFlags(dom, 0);
}

static virDomainPtr qemuDomainDefineXML(virConnectPtr conn, const char *xml) {
    virQEMUDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainDefPtr oldDef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    virQEMUCapsPtr qemuCaps = NULL;
    virQEMUDriverConfigPtr cfg;
    virCapsPtr caps = NULL;

    cfg = virQEMUDriverGetConfig(driver);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainDefineXMLEnsureACL(conn, def) < 0)
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

    def = NULL;
    if (virDomainHasDiskMirror(vm)) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE, "%s",
                       _("domain has active block copy job"));
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
            qemuDomainRemoveInactive(driver, vm);
            vm = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
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
    if (vm)
        virObjectUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    virObjectUnref(qemuCaps);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return dom;
}

static int
qemuDomainUndefineFlags(virDomainPtr dom,
                        unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    char *name = NULL;
    int ret = -1;
    int nsnapshots;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE |
                  VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA, -1);

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

    if (virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    VIR_INFO("Undefining domain '%s'", vm->def->name);

    /* If the domain is active, keep it running but set it as transient.
     * domainDestroy and domainShutdown will take care of removing the
     * domain obj from the hash table.
     */
    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }

    ret = 0;

cleanup:
    VIR_FREE(name);
    if (vm)
        virObjectUnlock(vm);
    if (event)
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
qemuDomainAttachDeviceControllerLive(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virDomainControllerDefPtr cont = dev->data.controller;
    int ret = -1;

    switch (cont->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        ret = qemuDomainAttachControllerDevice(driver, vm, cont);
        break;
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("'%s' controller cannot be hot plugged."),
                       virDomainControllerTypeToString(cont->type));
        break;
    }
    return ret;
}

static int
qemuDomainAttachDeviceLive(virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev,
                           virDomainPtr dom)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        qemuDomainObjCheckDiskTaint(driver, vm, dev->data.disk, -1);
        ret = qemuDomainAttachDeviceDiskLive(dom->conn, driver, vm, dev);
        if (!ret)
            dev->data.disk = NULL;
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        ret = qemuDomainAttachDeviceControllerLive(driver, vm, dev);
        if (!ret)
            dev->data.controller = NULL;
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
        ret = qemuDomainAttachLease(driver, vm,
                                    dev->data.lease);
        if (ret == 0)
            dev->data.lease = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        qemuDomainObjCheckNetTaint(driver, vm, dev->data.net, -1);
        ret = qemuDomainAttachNetDevice(dom->conn, driver, vm,
                                        dev->data.net);
        if (!ret)
            dev->data.net = NULL;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = qemuDomainAttachHostDevice(driver, vm,
                                         dev->data.hostdev);
        if (!ret)
            dev->data.hostdev = NULL;
        break;

    case VIR_DOMAIN_DEVICE_REDIRDEV:
        ret = qemuDomainAttachRedirdevDevice(driver, vm,
                                             dev->data.redirdev);
        if (!ret)
            dev->data.redirdev = NULL;
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainAttachChrDevice(driver, vm,
                                        dev->data.chr);
        if (!ret)
            dev->data.chr = NULL;
        break;

    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live attach of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    if (ret == 0)
        qemuDomainUpdateDeviceList(driver, vm);

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

    switch (dev->type) {
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
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live detach of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    if (ret == 0)
        qemuDomainUpdateDeviceList(driver, vm);

    return ret;
}

static int
qemuDomainChangeDiskMediaLive(virConnectPtr conn,
                              virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev,
                              virQEMUDriverPtr driver,
                              bool force)
{
    virDomainDiskDefPtr disk = dev->data.disk;
    virDomainDiskDefPtr orig_disk = NULL;
    virDomainDiskDefPtr tmp = NULL;
    virDomainDeviceDefPtr dev_copy = NULL;
    virCapsPtr caps = NULL;
    int ret = -1;

    if (qemuTranslateDiskSourcePool(conn, disk) < 0)
        goto end;

    if (qemuDomainDetermineDiskChain(driver, disk, false) < 0)
        goto end;

    if (qemuSetupDiskCgroup(vm, disk) < 0)
        goto end;

    switch (disk->device) {
    case VIR_DOMAIN_DISK_DEVICE_CDROM:
    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        if (!(orig_disk = virDomainDiskFindByBusAndDst(vm->def,
                                                       disk->bus, disk->dst))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("No device with bus '%s' and target '%s'"),
                           virDomainDiskBusTypeToString(disk->bus),
                           disk->dst);
            goto end;
        }

        if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
            goto end;

        tmp = dev->data.disk;
        dev->data.disk = orig_disk;

        if (!(dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                                caps, driver->xmlopt))) {
            dev->data.disk = tmp;
            goto end;
        }
        dev->data.disk = tmp;

        /* Add the new disk src into shared disk hash table */
        if (qemuAddSharedDevice(driver, dev, vm->def->name) < 0)
            goto end;

        ret = qemuDomainChangeEjectableMedia(driver, vm, disk, orig_disk, force);
        /* 'disk' must not be accessed now - it has been freed.
         * 'orig_disk' now points to the new disk, while 'dev_copy'
         * now points to the old disk */

        /* Need to remove the shared disk entry for the original
         * disk src if the operation is either ejecting or updating.
         */
        if (ret == 0) {
            dev->data.disk = NULL;
            ignore_value(qemuRemoveSharedDevice(driver, dev_copy,
                                                vm->def->name));
        }
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk bus '%s' cannot be updated."),
                       virDomainDiskBusTypeToString(disk->bus));
        break;
    }

    if (ret != 0 &&
        qemuTeardownDiskCgroup(vm, disk) < 0)
        VIR_WARN("Failed to teardown cgroup for disk path %s",
                 NULLSTR(disk->src));

end:
    virObjectUnref(caps);
    virDomainDeviceDefFree(dev_copy);
    return ret;
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

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        ret = qemuDomainChangeDiskMediaLive(conn, vm, dev, driver, force);
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        ret = qemuDomainChangeGraphics(driver, vm, dev->data.graphics);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        ret = qemuDomainChangeNet(driver, vm, dom, dev);
        break;
    default:
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
                             virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;
    virDomainNetDefPtr net;
    virDomainHostdevDefPtr hostdev;
    virDomainLeaseDefPtr lease;
    virDomainControllerDefPtr controller;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (virDomainDiskIndexByName(vmdef, disk->dst, true) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("target %s already exists"), disk->dst);
            return -1;
        }
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
        break;

    default:
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
    int idx;
    char mac[VIR_MAC_STRING_BUFLEN];

    switch (dev->type) {
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
        idx = virDomainNetFindIdx(vmdef, net);
        if (idx == -2) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("multiple devices matching mac address %s found"),
                           virMacAddrFormat(&net->mac, mac));
            return -1;
        } else if (idx < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("no matching network device was found"));
            return -1;
        }
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

    default:
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
    virDomainNetDefPtr net;
    int pos;
    char mac[VIR_MAC_STRING_BUFLEN];


    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        pos = virDomainDiskIndexByName(vmdef, disk->dst, false);
        if (pos < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("target %s doesn't exist."), disk->dst);
            return -1;
        }
        orig = vmdef->disks[pos];
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
        VIR_FREE(orig->src);
        orig->src = disk->src;
        orig->type = disk->type;
        orig->cachemode = disk->cachemode;
        if (disk->driverName) {
            VIR_FREE(orig->driverName);
            orig->driverName = disk->driverName;
            disk->driverName = NULL;
        }
        if (disk->format)
            orig->format = disk->format;
        disk->src = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        pos = virDomainNetFindIdx(vmdef, net);
        if (pos == -2) {
            virMacAddrFormat(&net->mac, mac);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("couldn't find matching device "
                             "with mac address %s"), mac);
            return -1;
        } else if (pos < 0) {
            virMacAddrFormat(&net->mac, mac);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("couldn't find matching device "
                             "with mac address %s"), mac);
            return -1;
        }

        virDomainNetDefFree(vmdef->nets[pos]);

        vmdef->nets[pos] = net;
        dev->data.net = NULL;

        if (qemuDomainAssignAddresses(vmdef, qemuCaps, NULL) < 0)
            return -1;
        break;

    default:
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
    unsigned int affect, parse_flags = 0;
    virQEMUCapsPtr qemuCaps = NULL;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    affect = flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot do live update a device on "
                             "inactive domain"));
            goto endjob;
        }
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot modify device on transient domain"));
         goto endjob;
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) &&
        !(flags & VIR_DOMAIN_AFFECT_LIVE))
        parse_flags |= VIR_DOMAIN_XML_INACTIVE;

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
        if (virDomainDefCompatibleDevice(vm->def, dev) < 0)
            goto endjob;

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;
        if ((ret = qemuDomainAttachDeviceConfig(qemuCaps, vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy) < 0)
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
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    virObjectUnref(qemuCaps);
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
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
    unsigned int affect;
    virQEMUCapsPtr qemuCaps = NULL;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_DEVICE_MODIFY_FORCE, -1);

    cfg = virQEMUDriverGetConfig(driver);

    affect = flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot do live update a device on "
                             "inactive domain"));
            goto endjob;
        }
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot modify device on transient domain"));
         goto endjob;
    }

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_XML_INACTIVE);
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
        if (virDomainDefCompatibleDevice(vm->def, dev) < 0)
            goto endjob;

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;

        if ((ret = qemuDomainUpdateDeviceConfig(qemuCaps, vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy) < 0)
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
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    virObjectUnref(qemuCaps);
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
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
    unsigned int affect, parse_flags = 0;
    virQEMUCapsPtr qemuCaps = NULL;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virQEMUDriverGetConfig(driver);

    affect = flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot do live update a device on "
                             "inactive domain"));
            goto endjob;
        }
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot modify device on transient domain"));
         goto endjob;
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) &&
        !(flags & VIR_DOMAIN_AFFECT_LIVE))
        parse_flags |= VIR_DOMAIN_XML_INACTIVE;

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
        if (virDomainDefCompatibleDevice(vm->def, dev) < 0)
            goto endjob;

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;
        if ((ret = qemuDomainDetachDeviceConfig(vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy) < 0)
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
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    virObjectUnref(qemuCaps);
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
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
                                  int *autostart) {
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int qemuDomainSetAutostart(virDomainPtr dom,
                                  int autostart) {
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
        if ((configFile = virDomainConfigFile(cfg->configDir, vm->def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virDomainConfigFile(cfg->autostartDir, vm->def->name)) == NULL)
            goto cleanup;

        if (autostart) {
            if (virFileMakePath(cfg->autostartDir) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %s"),
                                     cfg->autostartDir);
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
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}


static char *qemuDomainGetSchedulerType(virDomainPtr dom,
                                        int *nparams)
{
    char *ret = NULL;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

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
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

/* deviceWeightStr in the form of /device/path,weight,/device/path,weight
 * for example, /dev/disk/by-path/pci-0000:00:1f.2-scsi-0:0:0:0,800
 */
static int
qemuDomainParseDeviceWeightStr(char *deviceWeightStr,
                               virBlkioDeviceWeightPtr *dw, size_t *size)
{
    char *temp;
    int ndevices = 0;
    int nsep = 0;
    size_t i;
    virBlkioDeviceWeightPtr result = NULL;

    *dw = NULL;
    *size = 0;

    if (STREQ(deviceWeightStr, ""))
        return 0;

    temp = deviceWeightStr;
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
        goto error;

    ndevices = (nsep + 1) / 2;

    if (VIR_ALLOC_N(result, ndevices) < 0)
        return -1;

    i = 0;
    temp = deviceWeightStr;
    while (temp) {
        char *p = temp;

        /* device path */
        p = strchr(p, ',');
        if (!p)
            goto error;

        if (VIR_STRNDUP(result[i].path, temp, p - temp) < 0)
            goto cleanup;

        /* weight */
        temp = p + 1;

        if (virStrToLong_ui(temp, &p, 10, &result[i].weight) < 0)
            goto error;

        i++;

        if (*p == '\0')
            break;
        else if (*p != ',')
            goto error;
        temp = p + 1;
    }

    if (!i)
        VIR_FREE(result);

    *dw = result;
    *size = i;

    return 0;

error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("unable to parse device weight '%s'"), deviceWeightStr);
cleanup:
    virBlkioDeviceWeightArrayClear(result, ndevices);
    VIR_FREE(result);
    return -1;
}

/* Modify dest_array to reflect all device weight changes described in
 * src_array.  */
static int
qemuDomainMergeDeviceWeights(virBlkioDeviceWeightPtr *dest_array,
                             size_t *dest_size,
                             virBlkioDeviceWeightPtr src_array,
                             size_t src_size)
{
    size_t i, j;
    virBlkioDeviceWeightPtr dest, src;

    for (i = 0; i < src_size; i++) {
        bool found = false;

        src = &src_array[i];
        for (j = 0; j < *dest_size; j++) {
            dest = &(*dest_array)[j];
            if (STREQ(src->path, dest->path)) {
                found = true;
                dest->weight = src->weight;
                break;
            }
        }
        if (!found) {
            if (!src->weight)
                continue;
            if (VIR_EXPAND_N(*dest_array, *dest_size, 1) < 0)
                return -1;
            dest = &(*dest_array)[*dest_size - 1];
            dest->path = src->path;
            dest->weight = src->weight;
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
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BLKIO_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                               VIR_TYPED_PARAM_STRING,
                               NULL) < 0)
        return -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSetBlkioParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

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

    ret = 0;
    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                if (params[i].value.ui > 1000 || params[i].value.ui < 100) {
                    virReportError(VIR_ERR_INVALID_ARG, "%s",
                                   _("out of blkio weight range."));
                    ret = -1;
                    continue;
                }

                if (virCgroupSetBlkioWeight(priv->cgroup, params[i].value.ui) < 0)
                    ret = -1;
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                size_t ndevices;
                virBlkioDeviceWeightPtr devices = NULL;
                size_t j;

                if (qemuDomainParseDeviceWeightStr(params[i].value.s,
                                                   &devices,
                                                   &ndevices) < 0) {
                    ret = -1;
                    continue;
                }
                for (j = 0; j < ndevices; j++) {
                    if (virCgroupSetBlkioDeviceWeight(priv->cgroup,
                                                      devices[j].path,
                                                      devices[j].weight) < 0) {
                        ret = -1;
                        break;
                    }
                }
                if (j != ndevices ||
                    qemuDomainMergeDeviceWeights(&vm->def->blkio.devices,
                                                 &vm->def->blkio.ndevices,
                                                 devices, ndevices) < 0)
                    ret = -1;
                virBlkioDeviceWeightArrayClear(devices, ndevices);
                VIR_FREE(devices);
            }
        }
    }
    if (ret < 0)
        goto cleanup;
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Clang can't see that if we get here, persistentDef was set.  */
        sa_assert(persistentDef);

        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                if (params[i].value.ui > 1000 || params[i].value.ui < 100) {
                    virReportError(VIR_ERR_INVALID_ARG, "%s",
                                   _("out of blkio weight range."));
                    ret = -1;
                    continue;
                }

                persistentDef->blkio.weight = params[i].value.ui;
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                virBlkioDeviceWeightPtr devices = NULL;
                size_t ndevices;

                if (qemuDomainParseDeviceWeightStr(params[i].value.s,
                                                   &devices,
                                                   &ndevices) < 0) {
                    ret = -1;
                    continue;
                }
                if (qemuDomainMergeDeviceWeights(&persistentDef->blkio.devices,
                                                 &persistentDef->blkio.ndevices,
                                                 devices, ndevices) < 0)
                    ret = -1;
                virBlkioDeviceWeightArrayClear(devices, ndevices);
                VIR_FREE(devices);
            }
        }

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            ret = -1;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
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
                    if (virBufferError(&buf)) {
                        virReportOOMError();
                        goto cleanup;
                    }
                    param->value.s = virBufferContentAndReset(&buf);
                }
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                                            VIR_TYPED_PARAM_STRING,
                                            param->value.s) < 0)
                    goto cleanup;
                break;

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
                    if (virBufferError(&buf)) {
                        virReportOOMError();
                        goto cleanup;
                    }
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
    if (vm)
        virObjectUnlock(vm);
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

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup memory controller is not mounted"));
            goto cleanup;
        }
    }

#define VIR_GET_LIMIT_PARAMETER(PARAM, VALUE)                                \
    if ((rc = virTypedParamsGetULLong(params, nparams, PARAM, &VALUE)) < 0)  \
        goto cleanup;                                                        \
                                                                             \
    if (rc == 1)                                                             \
        set_ ## VALUE = true;

    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT, swap_hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_HARD_LIMIT, hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SOFT_LIMIT, soft_limit)

#undef VIR_GET_LIMIT_PARAMETER

    /* Swap hard limit must be greater than hard limit.
     * Note that limit of 0 denotes unlimited */
    if (set_swap_hard_limit || set_hard_limit) {
        unsigned long long mem_limit = vm->def->mem.hard_limit;
        unsigned long long swap_limit = vm->def->mem.swap_hard_limit;

        if (set_swap_hard_limit)
            swap_limit = swap_hard_limit;

        if (set_hard_limit)
            mem_limit = hard_limit;

        if (virCompareLimitUlong(mem_limit, swap_limit) > 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("memory hard_limit tunable value must be lower "
                             "than swap_hard_limit"));
            goto cleanup;
        }
    }

#define QEMU_SET_MEM_PARAMETER(FUNC, VALUE)                                     \
    if (set_ ## VALUE) {                                                        \
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {                                   \
            if ((rc = FUNC(priv->cgroup, VALUE)) < 0) {                         \
                virReportSystemError(-rc, _("unable to set memory %s tunable"), \
                                     #VALUE);                                   \
                                                                                \
                goto cleanup;                                                   \
            }                                                                   \
            vm->def->mem.VALUE = VALUE;                                         \
        }                                                                       \
                                                                                \
        if (flags & VIR_DOMAIN_AFFECT_CONFIG)                                   \
            persistentDef->mem.VALUE = VALUE;                                   \
    }

    /* Soft limit doesn't clash with the others */
    QEMU_SET_MEM_PARAMETER(virCgroupSetMemorySoftLimit, soft_limit);

    /* set hard limit before swap hard limit if decreasing it */
    if (virCompareLimitUlong(vm->def->mem.hard_limit, hard_limit) > 0) {
        QEMU_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);
        /* inhibit changing the limit a second time */
        set_hard_limit = false;
    }

    QEMU_SET_MEM_PARAMETER(virCgroupSetMemSwapHardLimit, swap_hard_limit);

    /* otherwise increase it after swap hard limit */
    QEMU_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);

#undef QEMU_SET_MEM_PARAMETER

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetMemoryParameters(virDomainPtr dom,
                              virTypedParameterPtr params,
                              int *nparams,
                              unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainGetMemoryParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup memory controller is not mounted"));
            goto cleanup;
        }
    }

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = QEMU_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        for (i = 0; i < *nparams && i < QEMU_NB_MEM_PARAM; i++) {
            virMemoryParameterPtr param = &params[i];

            switch (i) {
            case 0: /* fill memory hard limit here */
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                            VIR_TYPED_PARAM_ULLONG,
                                            persistentDef->mem.hard_limit) < 0)
                    goto cleanup;
                break;

            case 1: /* fill memory soft limit here */
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                            VIR_TYPED_PARAM_ULLONG,
                                            persistentDef->mem.soft_limit) < 0)
                    goto cleanup;
                break;

            case 2: /* fill swap hard limit here */
                if (virTypedParameterAssign(param,
                                            VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                            VIR_TYPED_PARAM_ULLONG,
                                            persistentDef->mem.swap_hard_limit) < 0)
                    goto cleanup;
                break;

            default:
                break;
                /* should not hit here */
            }
        }
        goto out;
    }

    for (i = 0; i < *nparams && i < QEMU_NB_MEM_PARAM; i++) {
        virTypedParameterPtr param = &params[i];
        unsigned long long val = 0;

        switch (i) {
        case 0: /* fill memory hard limit here */
            if (virCgroupGetMemoryHardLimit(priv->cgroup, &val) < 0)
                goto cleanup;
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        case 1: /* fill memory soft limit here */
            if (virCgroupGetMemorySoftLimit(priv->cgroup, &val) < 0)
                goto cleanup;
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        case 2: /* fill swap hard limit here */
            if (virCgroupGetMemSwapHardLimit(priv->cgroup, &val) < 0) {
                if (!virLastErrorIsSystemErrno(ENOENT) &&
                    !virLastErrorIsSystemErrno(EOPNOTSUPP))
                    goto cleanup;
                val = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
            }
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        default:
            break;
            /* should not hit here */
        }
    }

out:
    if (QEMU_NB_MEM_PARAM < *nparams)
        *nparams = QEMU_NB_MEM_PARAM;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
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
    virDomainDefPtr persistentDef = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv;

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

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup cpuset controller is not mounted"));
            goto cleanup;
        }
    }

    ret = 0;
    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_NUMA_MODE)) {
            if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
                vm->def->numatune.memory.mode != params[i].value.i) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("can't change numa mode for running domain"));
                ret = -1;
                goto cleanup;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                persistentDef->numatune.memory.mode = params[i].value.i;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_NUMA_NODESET)) {
            virBitmapPtr nodeset = NULL;
            char *nodeset_str = NULL;

            if (virBitmapParse(params[i].value.s,
                               0, &nodeset,
                               VIR_DOMAIN_CPUMASK_LEN) < 0) {
                ret = -1;
                continue;
            }

            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                if (vm->def->numatune.memory.mode !=
                    VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
                    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                   _("change of nodeset for running domain "
                                     "requires strict numa mode"));
                    virBitmapFree(nodeset);
                    ret = -1;
                    continue;
                }

                /* Ensure the cpuset string is formated before passing to cgroup */
                if (!(nodeset_str = virBitmapFormat(nodeset))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Failed to format nodeset"));
                    virBitmapFree(nodeset);
                    ret = -1;
                    continue;
                }

                if (virCgroupSetCpusetMems(priv->cgroup, nodeset_str) < 0) {
                    virBitmapFree(nodeset);
                    VIR_FREE(nodeset_str);
                    ret = -1;
                    continue;
                }
                VIR_FREE(nodeset_str);

                /* update vm->def here so that dumpxml can read the new
                 * values from vm->def. */
                virBitmapFree(vm->def->numatune.memory.nodemask);

                vm->def->numatune.memory.placement_mode =
                    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_STATIC;
                vm->def->numatune.memory.nodemask = virBitmapNewCopy(nodeset);
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                virBitmapFree(persistentDef->numatune.memory.nodemask);

                persistentDef->numatune.memory.nodemask = nodeset;
                persistentDef->numatune.memory.placement_mode =
                    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_STATIC;
                nodeset = NULL;
            }
            virBitmapFree(nodeset);
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!persistentDef->numatune.memory.placement_mode)
            persistentDef->numatune.memory.placement_mode =
                VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO;
        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            ret = -1;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainGetNumaParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    char *nodeset = NULL;
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

    if (virDomainGetNumaParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        *nparams = QEMU_NB_NUMA_PARAM;
        ret = 0;
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup memory controller is not mounted"));
            goto cleanup;
        }
    }

    for (i = 0; i < QEMU_NB_NUMA_PARAM && i < *nparams; i++) {
        virMemoryParameterPtr param = &params[i];

        switch (i) {
        case 0: /* fill numa mode here */
            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_MODE,
                                        VIR_TYPED_PARAM_INT, 0) < 0)
                goto cleanup;
            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                param->value.i = persistentDef->numatune.memory.mode;
            else
                param->value.i = vm->def->numatune.memory.mode;
            break;

        case 1: /* fill numa nodeset here */
            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                nodeset = virBitmapFormat(persistentDef->numatune.memory.nodemask);
                if (!nodeset && VIR_STRDUP(nodeset, "") < 0)
                    goto cleanup;
            } else {
                if (virCgroupGetCpusetMems(priv->cgroup, &nodeset) < 0)
                    goto cleanup;
            }
            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_NODESET,
                                        VIR_TYPED_PARAM_STRING, nodeset) < 0)
                goto cleanup;

            nodeset = NULL;

            break;

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
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
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

    /* If we does not know VCPU<->PID mapping or all vcpu runs in the same
     * thread, we cannot control each vcpu. So we only modify cpu bandwidth
     * when each vcpu has a separated thread.
     */
    if (priv->nvcpupids != 0 && priv->vcpupids[0] != vm->pid) {
        for (i = 0; i < priv->nvcpupids; i++) {
            if (virCgroupNewVcpu(cgroup, i, false, &cgroup_vcpu) < 0)
                goto cleanup;

            if (qemuSetupCgroupVcpuBW(cgroup_vcpu, period, quota) < 0)
                goto cleanup;

            virCgroupFree(&cgroup_vcpu);
        }
    }

    return 0;

cleanup:
    virCgroupFree(&cgroup_vcpu);
    return -1;
}

static int
qemuSetEmulatorBandwidthLive(virDomainObjPtr vm, virCgroupPtr cgroup,
                             unsigned long long period, long long quota)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup_emulator = NULL;

    if (period == 0 && quota == 0)
        return 0;

    if (priv->nvcpupids == 0 || priv->vcpupids[0] == vm->pid) {
        return 0;
    }

    if (virCgroupNewEmulator(cgroup, false, &cgroup_emulator) < 0)
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
        goto cleanup;                                                       \
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

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &vmdef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup CPU controller is not mounted"));
            goto cleanup;
        }
    }

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];
        value_ul = param->value.ul;
        value_l = param->value.l;

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CPU_SHARES)) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                if (virCgroupSetCpuShares(priv->cgroup, value_ul) < 0)
                    goto cleanup;
                vm->def->cputune.shares = value_ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.shares = value_ul;

        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_PERIOD)) {
            SCHED_RANGE_CHECK(value_ul, VIR_DOMAIN_SCHEDULER_VCPU_PERIOD,
                              QEMU_SCHED_MIN_PERIOD, QEMU_SCHED_MAX_PERIOD);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_ul) {
                if ((rc = qemuSetVcpusBWLive(vm, priv->cgroup, value_ul, 0)))
                    goto cleanup;

                vm->def->cputune.period = value_ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.period = params[i].value.ul;

        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_QUOTA)) {
            SCHED_RANGE_CHECK(value_l, VIR_DOMAIN_SCHEDULER_VCPU_QUOTA,
                              QEMU_SCHED_MIN_QUOTA, QEMU_SCHED_MAX_QUOTA);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_l) {
                if ((rc = qemuSetVcpusBWLive(vm, priv->cgroup, 0, value_l)))
                    goto cleanup;

                vm->def->cputune.quota = value_l;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.quota = value_l;

        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD)) {
            SCHED_RANGE_CHECK(value_ul, VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD,
                              QEMU_SCHED_MIN_PERIOD, QEMU_SCHED_MAX_PERIOD);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_ul) {
                if ((rc = qemuSetEmulatorBandwidthLive(vm, priv->cgroup,
                                                       value_ul, 0)))
                    goto cleanup;

                vm->def->cputune.emulator_period = value_ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.emulator_period = value_ul;

        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA)) {
            SCHED_RANGE_CHECK(value_l, VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA,
                              QEMU_SCHED_MIN_QUOTA, QEMU_SCHED_MAX_QUOTA);

            if (flags & VIR_DOMAIN_AFFECT_LIVE && value_l) {
                if ((rc = qemuSetEmulatorBandwidthLive(vm, priv->cgroup,
                                                       0, value_l)))
                    goto cleanup;

                vm->def->cputune.emulator_quota = value_l;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG)
                vmdef->cputune.emulator_quota = value_l;
        }
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto cleanup;


    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        rc = virDomainSaveConfig(cfg->configDir, vmdef);
        if (rc < 0)
            goto cleanup;

        virDomainObjAssignDef(vm, vmdef, false, NULL);
        vmdef = NULL;
    }

    ret = 0;

cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virObjectUnlock(vm);
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
    if (priv->nvcpupids == 0 || priv->vcpupids[0] == vm->pid) {
        /* We do not create sub dir for each vcpu */
        rc = qemuGetVcpuBWLive(priv->cgroup, period, quota);
        if (rc < 0)
            goto cleanup;

        if (*quota > 0)
            *quota /= vm->def->vcpus;
        goto out;
    }

    /* get period and quota for vcpu0 */
    if (virCgroupNewVcpu(priv->cgroup, 0, false, &cgroup_vcpu) < 0)
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
qemuGetEmulatorBandwidthLive(virDomainObjPtr vm, virCgroupPtr cgroup,
                             unsigned long long *period, long long *quota)
{
    virCgroupPtr cgroup_emulator = NULL;
    qemuDomainObjPrivatePtr priv = NULL;
    int rc;
    int ret = -1;

    priv = vm->privateData;
    if (priv->nvcpupids == 0 || priv->vcpupids[0] == vm->pid) {
        /* We don't create sub dir for each vcpu */
        *period = 0;
        *quota = 0;
        return 0;
    }

    /* get period and quota for emulator */
    if (virCgroupNewEmulator(cgroup, false, &cgroup_emulator) < 0)
        goto cleanup;

    rc = qemuGetVcpuBWLive(cgroup_emulator, period, quota);
    if (rc < 0)
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
        rc = qemuGetEmulatorBandwidthLive(vm, priv->cgroup, &emulator_period,
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
    if (vm)
        virObjectUnlock(vm);
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
    int ret = -1, idx;
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

    if ((idx = virDomainDiskIndexByName(vm->def, path, false)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path: %s"), path);
        goto endjob;
    }
    disk = vm->def->disks[idx];

    if (virAsprintf(&device, "%s%s", QEMU_DRIVE_HOST_PREFIX,
                    disk->info.alias) < 0)
        goto endjob;

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorBlockResize(priv->mon, device, size) < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        goto endjob;
    }
    qemuDomainObjExitMonitor(driver, vm);

    ret = 0;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    VIR_FREE(device);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

/* This uses the 'info blockstats' monitor command which was
 * integrated into both qemu & kvm in late 2007.  If the command is
 * not supported we detect this and return the appropriate error.
 */
static int
qemuDomainBlockStats(virDomainPtr dom,
                     const char *path,
                     struct _virDomainBlockStats *stats)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    int idx;
    int ret = -1;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk = NULL;
    qemuDomainObjPrivatePtr priv;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainBlockStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if ((idx = virDomainDiskIndexByName(vm->def, path, false)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path: %s"), path);
        goto cleanup;
    }
    disk = vm->def->disks[idx];

    if (!disk->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing disk device alias name for %s"), disk->dst);
        goto cleanup;
    }

    priv = vm->privateData;
    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorGetBlockStatsInfo(priv->mon,
                                       disk->info.alias,
                                       &stats->rd_req,
                                       &stats->rd_bytes,
                                       NULL,
                                       &stats->wr_req,
                                       &stats->wr_bytes,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &stats->errs);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    int idx;
    int tmp, ret = -1;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk = NULL;
    qemuDomainObjPrivatePtr priv;
    long long rd_req, rd_bytes, wr_req, wr_bytes, rd_total_times;
    long long wr_total_times, flush_req, flush_total_times, errs;
    virTypedParameterPtr param;

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

    if (*nparams != 0) {
        if ((idx = virDomainDiskIndexByName(vm->def, path, false)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("invalid path: %s"), path);
            goto endjob;
        }
        disk = vm->def->disks[idx];

        if (!disk->info.alias) {
             virReportError(VIR_ERR_INTERNAL_ERROR,
                            _("missing disk device alias name for %s"),
                            disk->dst);
             goto endjob;
        }
    }

    priv = vm->privateData;
    VIR_DEBUG("priv=%p, params=%p, flags=%x", priv, params, flags);

    qemuDomainObjEnterMonitor(driver, vm);
    tmp = *nparams;
    ret = qemuMonitorGetBlockStatsParamsNumber(priv->mon, nparams);

    if (tmp == 0 || ret < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        goto endjob;
    }

    ret = qemuMonitorGetBlockStatsInfo(priv->mon,
                                       disk->info.alias,
                                       &rd_req,
                                       &rd_bytes,
                                       &rd_total_times,
                                       &wr_req,
                                       &wr_bytes,
                                       &wr_total_times,
                                       &flush_req,
                                       &flush_total_times,
                                       &errs);

    qemuDomainObjExitMonitor(driver, vm);

    if (ret < 0)
        goto endjob;

    tmp = 0;
    ret = -1;

    if (tmp < *nparams && wr_bytes != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES,
                                    VIR_TYPED_PARAM_LLONG, wr_bytes) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && wr_req != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_WRITE_REQ,
                                    VIR_TYPED_PARAM_LLONG, wr_req) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && rd_bytes != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_READ_BYTES,
                                    VIR_TYPED_PARAM_LLONG, rd_bytes) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && rd_req != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_READ_REQ,
                                    VIR_TYPED_PARAM_LLONG, rd_req) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && flush_req != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ,
                                    VIR_TYPED_PARAM_LLONG, flush_req) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && wr_total_times != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param,
                                    VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES,
                                    VIR_TYPED_PARAM_LLONG, wr_total_times) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && rd_total_times != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param,
                                    VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES,
                                    VIR_TYPED_PARAM_LLONG, rd_total_times) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && flush_total_times != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param,
                                    VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES,
                                    VIR_TYPED_PARAM_LLONG,
                                    flush_total_times) < 0)
            goto endjob;
        tmp++;
    }

    /* Field 'errs' is meaningless for QEMU, won't set it. */

    ret = 0;
    *nparams = tmp;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

#ifdef __linux__
static int
qemuDomainInterfaceStats(virDomainPtr dom,
                         const char *path,
                         struct _virDomainInterfaceStats *stats)
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
        ret = linuxDomainInterfaceStats(path, stats);
    else
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path, '%s' is not a known interface"), path);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}
#else
static int
qemuDomainInterfaceStats(virDomainPtr dom ATTRIBUTE_UNUSED,
                         const char *path ATTRIBUTE_UNUSED,
                         struct _virDomainInterfaceStats *stats ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("interface stats not implemented on this platform"));
    return -1;
}
#endif

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
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    virDomainNetDefPtr net = NULL, persistentNet = NULL;
    virNetDevBandwidthPtr bandwidth = NULL, newBandwidth = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BANDWIDTH_IN_AVERAGE,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_IN_PEAK,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BANDWIDTH_IN_BURST,
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

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        net = virDomainNetFind(vm->def, device);
        if (!net) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Can't find device %s"), device);
            goto cleanup;
        }
    }
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        persistentNet = virDomainNetFind(persistentDef, device);
        if (!persistentNet) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Can't find device %s"), device);
            goto cleanup;
        }
    }

    if ((VIR_ALLOC(bandwidth) < 0) ||
        (VIR_ALLOC(bandwidth->in) < 0) ||
        (VIR_ALLOC(bandwidth->out) < 0))
        goto cleanup;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_IN_AVERAGE)) {
            bandwidth->in->average = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_IN_PEAK)) {
            bandwidth->in->peak = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_IN_BURST)) {
            bandwidth->in->burst = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE)) {
            bandwidth->out->average = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_OUT_PEAK)) {
            bandwidth->out->peak = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_BANDWIDTH_OUT_BURST)) {
            bandwidth->out->burst = params[i].value.ui;
        }
    }

    /* average is mandatory, peak and burst are optional. So if no
     * average is given, we free inbound/outbound here which causes
     * inbound/outbound to not be set. */
    if (!bandwidth->in->average) {
        VIR_FREE(bandwidth->in);
    }
    if (!bandwidth->out->average) {
        VIR_FREE(bandwidth->out);
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (VIR_ALLOC(newBandwidth) < 0)
            goto cleanup;

        /* virNetDevBandwidthSet() will clear any previous value of
         * bandwidth parameters, so merge with old bandwidth parameters
         * here to prevent them from being lost. */
        if (bandwidth->in ||
            (net->bandwidth && net->bandwidth->in)) {
            if (VIR_ALLOC(newBandwidth->in) < 0)
                goto cleanup;

            memcpy(newBandwidth->in,
                   bandwidth->in ? bandwidth->in : net->bandwidth->in,
                   sizeof(*newBandwidth->in));
        }
        if (bandwidth->out ||
            (net->bandwidth && net->bandwidth->out)) {
            if (VIR_ALLOC(newBandwidth->out) < 0)
                goto cleanup;

            memcpy(newBandwidth->out,
                   bandwidth->out ? bandwidth->out : net->bandwidth->out,
                   sizeof(*newBandwidth->out));
        }

        if (virNetDevBandwidthSet(net->ifname, newBandwidth, false) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot set bandwidth limits on %s"),
                           device);
            goto cleanup;
        }

        virNetDevBandwidthFree(net->bandwidth);
        net->bandwidth = newBandwidth;
        newBandwidth = NULL;
    }
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!persistentNet->bandwidth) {
            persistentNet->bandwidth = bandwidth;
            bandwidth = NULL;
        } else {
            if (bandwidth->in) {
                VIR_FREE(persistentNet->bandwidth->in);
                persistentNet->bandwidth->in = bandwidth->in;
                bandwidth->in = NULL;
            }
            if (bandwidth->out) {
                VIR_FREE(persistentNet->bandwidth->out);
                persistentNet->bandwidth->out = bandwidth->out;
                bandwidth->out = NULL;
            }
        }

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    virNetDevBandwidthFree(bandwidth);
    virNetDevBandwidthFree(newBandwidth);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
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
    virQEMUDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainDefPtr persistentDef = NULL;
    virDomainNetDefPtr net = NULL;
    int ret = -1;
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetInterfaceParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        *nparams = QEMU_NB_BANDWIDTH_PARAM;
        ret = 0;
        goto cleanup;
    }

    def = persistentDef;
    if (!def)
        def = vm->def;

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
        case 3: /* outbound.average */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->out)
                params[i].value.ui = net->bandwidth->out->average;
            break;
        case 4: /* outbound.peak */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_OUT_PEAK,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->out)
                params[i].value.ui = net->bandwidth->out->peak;
            break;
        case 5: /* outbound.burst */
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_BANDWIDTH_OUT_BURST,
                                        VIR_TYPED_PARAM_UINT, 0) < 0)
                goto cleanup;
            if (net->bandwidth && net->bandwidth->out)
                params[i].value.ui = net->bandwidth->out->burst;
            break;
        default:
            break;
            /* should not hit here */
        }
    }

    if (*nparams > QEMU_NB_BANDWIDTH_PARAM)
        *nparams = QEMU_NB_BANDWIDTH_PARAM;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    return ret;
}

static int
qemuDomainMemoryStats(virDomainPtr dom,
                      struct _virDomainMemoryStat *stats,
                      unsigned int nr_stats,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

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
    } else {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorGetMemoryStats(priv->mon, stats, nr_stats);
        qemuDomainObjExitMonitor(driver, vm);

        if (ret >= 0 && ret < nr_stats) {
            long rss;
            if (qemuGetProcessInfo(NULL, NULL, &rss, vm->pid, 0) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("cannot get RSS for domain"));
            } else {
                stats[ret].tag = VIR_DOMAIN_MEMORY_STAT_RSS;
                stats[ret].val = rss;
                ret++;
            }

        }
    }

    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    if (!path || path[0] == '\0') {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("NULL or empty path"));
        goto cleanup;
    }

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
    if (vm)
        virObjectUnlock(vm);
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
            qemuDomainObjExitMonitor(driver, vm);
            goto endjob;
        }
    } else {
        if (qemuMonitorSavePhysicalMemory(priv->mon, offset, size, tmp) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            goto endjob;
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

    /* Read the memory file into buffer. */
    if (saferead(fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError(errno,
                             _("failed to read temporary file "
                               "created with template %s"), tmp);
        goto endjob;
    }

    ret = 0;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    VIR_FORCE_CLOSE(fd);
    if (tmp)
        unlink(tmp);
    VIR_FREE(tmp);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}


static int qemuDomainGetBlockInfo(virDomainPtr dom,
                                  const char *path,
                                  virDomainBlockInfoPtr info,
                                  unsigned int flags) {
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    int fd = -1;
    off_t end;
    virStorageFileMetadata *meta = NULL;
    virDomainDiskDefPtr disk = NULL;
    struct stat sb;
    int idx;
    int format;
    virQEMUDriverConfigPtr cfg = NULL;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainGetBlockInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!path || path[0] == '\0') {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("NULL or empty path"));
        goto cleanup;
    }

    /* Check the path belongs to this domain. */
    if ((idx = virDomainDiskIndexByName(vm->def, path, false)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path %s not assigned to domain"), path);
        goto cleanup;
    }
    disk = vm->def->disks[idx];
    if (!disk->src) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("disk %s does not currently have a source assigned"),
                       path);
        goto cleanup;
    }
    path = disk->src;

    /* The path is correct, now try to open it and get its size. */
    fd = qemuOpenFile(driver, vm, path, O_RDONLY, NULL, NULL);
    if (fd == -1)
        goto cleanup;

    /* Probe for magic formats */
    if (disk->format) {
        format = disk->format;
    } else {
        if (cfg->allowDiskFormatProbing) {
            if ((format = virStorageFileProbeFormat(disk->src,
                                                    cfg->user,
                                                    cfg->group)) < 0)
                goto cleanup;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("no disk format for %s and probing is disabled"),
                           disk->src);
            goto cleanup;
        }
    }

    if (!(meta = virStorageFileGetMetadataFromFD(path, fd, format)))
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
        end = lseek(fd, 0, SEEK_END);
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
    if (meta->capacity)
        info->capacity = meta->capacity;

    /* Set default value .. */
    info->allocation = info->physical;

    /* ..but if guest is running & not using raw
       disk format and on a block device, then query
       highest allocated extent from QEMU */
    if (disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK &&
        format != VIR_STORAGE_FILE_RAW &&
        S_ISBLK(sb.st_mode) &&
        virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;

        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
            goto cleanup;

        if (virDomainObjIsActive(vm)) {
            qemuDomainObjEnterMonitor(driver, vm);
            ret = qemuMonitorGetBlockExtent(priv->mon,
                                            disk->info.alias,
                                            &info->allocation);
            qemuDomainObjExitMonitor(driver, vm);
        } else {
            ret = 0;
        }

        if (!qemuDomainObjEndJob(driver, vm))
            vm = NULL;
    } else {
        ret = 0;
    }

cleanup:
    virStorageFileFreeMetadata(meta);
    VIR_FORCE_CLOSE(fd);
    if (vm)
        virObjectUnlock(vm);
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

    if (virDomainEventStateDeregisterID(conn,
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
                                     &def, origname, NULL, flags);

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

    if (virDomainMigratePerformEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

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
                               NULL, dconnuri, uri, NULL, NULL,
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
        goto cleanup;
    }

    if (virDomainMigrateFinish2EnsureACL(dconn, vm->def) < 0)
        goto cleanup;

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
        virObjectUnlock(vm);
        return NULL;
    }

    return qemuMigrationBegin(domain->conn, vm, xmlin, dname,
                              cookieout, cookieoutlen, flags);
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
    virDomainObjPtr vm;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        return NULL;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &xmlin) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0)
        return NULL;

    if (!(vm = qemuDomObjFromDomain(domain)))
        return NULL;

    if (virDomainMigrateBegin3ParamsEnsureACL(domain->conn, vm->def) < 0) {
        virObjectUnlock(vm);
        return NULL;
    }

    return qemuMigrationBegin(domain->conn, vm, xmlin, dname,
                              cookieout, cookieoutlen, flags);
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
                                     &def, origname, NULL, flags);

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
                                     &def, origname, listenAddress, flags);

cleanup:
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
        virObjectUnlock(vm);
        return -1;
    }

    return qemuMigrationPerform(driver, dom->conn, vm, xmlin,
                                dconnuri, uri, NULL, NULL,
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
    unsigned long long bandwidth = 0;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, QEMU_MIGRATION_PARAMETERS) < 0)
        return -1;

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
        return -1;

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainMigratePerform3ParamsEnsureACL(dom->conn, vm->def) < 0) {
        virObjectUnlock(vm);
        return -1;
    }

    return qemuMigrationPerform(driver, dom->conn, vm, dom_xml,
                                dconnuri, uri, graphicsuri, listenAddress,
                                cookiein, cookieinlen, cookieout, cookieoutlen,
                                flags, dname, bandwidth, true);
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

    if (!dname ||
        !(vm = virDomainObjListFindByName(driver->domains, dname))) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"),
                       NULLSTR(dname));
        return NULL;
    }

    if (virDomainMigrateFinish3EnsureACL(dconn, vm->def) < 0) {
        virObjectUnlock(vm);
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

    if (!dname ||
        !(vm = virDomainObjListFindByName(driver->domains, dname))) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"),
                       NULLSTR(dname));
        return NULL;
    }

    if (virDomainMigrateFinish3ParamsEnsureACL(dconn, vm->def) < 0) {
        virObjectUnlock(vm);
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
        virObjectUnlock(vm);
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
        virObjectUnlock(vm);
        return -1;
    }

    return qemuMigrationConfirm(domain->conn, vm, cookiein, cookieinlen,
                                flags, cancelled);
}


static int
qemuNodeDeviceGetPciInfo(virNodeDeviceDefPtr def,
                         unsigned *domain,
                         unsigned *bus,
                         unsigned *slot,
                         unsigned *function)
{
    virNodeDevCapsDefPtr cap;
    int ret = -1;

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

    virCheckFlags(0, -1);

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceDetachFlagsEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (qemuNodeDeviceGetPciInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    if (!driverName || STREQ(driverName, "kvm")) {
        if (virPCIDeviceSetStubDriver(pci, "pci-stub") < 0)
            goto cleanup;
    } else if (STREQ(driverName, "vfio")) {
        if (virPCIDeviceSetStubDriver(pci, "vfio-pci") < 0)
            goto cleanup;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown driver name '%s'"), driverName);
        goto cleanup;
    }

    virObjectLock(driver->activePciHostdevs);
    virObjectLock(driver->inactivePciHostdevs);

    if (virPCIDeviceDetach(pci, driver->activePciHostdevs,
                           driver->inactivePciHostdevs) < 0) {
        goto out;
    }

    ret = 0;
out:
    virObjectUnlock(driver->inactivePciHostdevs);
    virObjectUnlock(driver->activePciHostdevs);
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
    virPCIDevicePtr other;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;
    virNodeDeviceDefPtr def = NULL;
    char *xml = NULL;

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceReAttachEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (qemuNodeDeviceGetPciInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    virObjectLock(driver->activePciHostdevs);
    virObjectLock(driver->inactivePciHostdevs);
    other = virPCIDeviceListFind(driver->activePciHostdevs, pci);
    if (other) {
        const char *other_name = virPCIDeviceGetUsedBy(other);

        if (other_name)
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %s is still in use by domain %s"),
                           virPCIDeviceGetName(pci), other_name);
        else
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %s is still in use"),
                           virPCIDeviceGetName(pci));
        goto out;
    }

    virPCIDeviceReattachInit(pci);

    if (virPCIDeviceReattach(pci, driver->activePciHostdevs,
                             driver->inactivePciHostdevs) < 0)
        goto out;

    ret = 0;
out:
    virObjectUnlock(driver->inactivePciHostdevs);
    virObjectUnlock(driver->activePciHostdevs);
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

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceResetEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (qemuNodeDeviceGetPciInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    virObjectLock(driver->activePciHostdevs);
    virObjectLock(driver->inactivePciHostdevs);

    if (virPCIDeviceReset(pci, driver->activePciHostdevs,
                          driver->inactivePciHostdevs) < 0)
        goto out;

    ret = 0;
out:
    virObjectUnlock(driver->inactivePciHostdevs);
    virObjectUnlock(driver->activePciHostdevs);
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

    virCheckFlags(0, VIR_CPU_COMPARE_ERROR);

    if (virConnectCompareCPUEnsureACL(conn) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!caps->host.cpu ||
        !caps->host.cpu->model) {
        VIR_WARN("cannot get host CPU capabilities");
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
    } else {
        ret = cpuCompareXML(caps->host.cpu, xmlDesc);
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

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, NULL);

    if (virConnectBaselineCPUEnsureACL(conn) < 0)
        goto cleanup;

    cpu = cpuBaselineXML(xmlCPUs, ncpus, NULL, 0, flags);

cleanup:
    return cpu;
}


static int qemuDomainGetJobInfo(virDomainPtr dom,
                                virDomainJobInfoPtr info) {
    virDomainObjPtr vm;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetJobInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (priv->job.asyncJob && !priv->job.dump_memory_only) {
            memcpy(info, &priv->job.info, sizeof(*info));

            /* Refresh elapsed time again just to ensure it
             * is fully updated. This is primarily for benefit
             * of incoming migration which we don't currently
             * monitor actively in the background thread
             */
            if (virTimeMillisNow(&info->timeElapsed) < 0)
                goto cleanup;
            info->timeElapsed -= priv->job.start;
        } else {
            memset(info, 0, sizeof(*info));
            info->type = VIR_DOMAIN_JOB_NONE;
        }
    } else {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
qemuDomainGetJobStats(virDomainPtr dom,
                      int *type,
                      virTypedParameterPtr *params,
                      int *nparams,
                      unsigned int flags)
{
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    virTypedParameterPtr par = NULL;
    int maxpar = 0;
    int npar = 0;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetJobStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!priv->job.asyncJob || priv->job.dump_memory_only) {
        *type = VIR_DOMAIN_JOB_NONE;
        *params = NULL;
        *nparams = 0;
        ret = 0;
        goto cleanup;
    }

    /* Refresh elapsed time again just to ensure it
     * is fully updated. This is primarily for benefit
     * of incoming migration which we don't currently
     * monitor actively in the background thread
     */
    if (virTimeMillisNow(&priv->job.info.timeElapsed) < 0)
        goto cleanup;
    priv->job.info.timeElapsed -= priv->job.start;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_ELAPSED,
                                priv->job.info.timeElapsed) < 0)
        goto cleanup;

    if (priv->job.info.type == VIR_DOMAIN_JOB_BOUNDED &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_REMAINING,
                                priv->job.info.timeRemaining) < 0)
        goto cleanup;

    if (priv->job.status.downtime_set &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DOWNTIME,
                                priv->job.status.downtime) < 0)
        goto cleanup;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_TOTAL,
                                priv->job.info.dataTotal) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_PROCESSED,
                                priv->job.info.dataProcessed) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_REMAINING,
                                priv->job.info.dataRemaining) < 0)
        goto cleanup;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_TOTAL,
                                priv->job.info.memTotal) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_PROCESSED,
                                priv->job.info.memProcessed) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_REMAINING,
                                priv->job.info.memRemaining) < 0)
        goto cleanup;

    if (priv->job.status.ram_duplicate_set) {
        if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_CONSTANT,
                                    priv->job.status.ram_duplicate) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_NORMAL,
                                    priv->job.status.ram_normal) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES,
                                    priv->job.status.ram_normal_bytes) < 0)
            goto cleanup;
    }

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_TOTAL,
                                priv->job.info.fileTotal) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_PROCESSED,
                                priv->job.info.fileProcessed) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_REMAINING,
                                priv->job.info.fileRemaining) < 0)
        goto cleanup;

    if (priv->job.status.xbzrle_set) {
        if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_CACHE,
                                    priv->job.status.xbzrle_cache_size) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_BYTES,
                                    priv->job.status.xbzrle_bytes) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_PAGES,
                                    priv->job.status.xbzrle_pages) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES,
                                    priv->job.status.xbzrle_cache_miss) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW,
                                    priv->job.status.xbzrle_overflow) < 0)
            goto cleanup;
    }

    *type = priv->job.info.type;
    *params = par;
    *nparams = npar;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (ret < 0)
        virTypedParamsFree(par, npar);
    return ret;
}


static int qemuDomainAbortJob(virDomainPtr dom) {
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
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    if (priv->job.asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not being migrated"));
        goto endjob;
    }

    VIR_DEBUG("Setting migration downtime to %llums", downtime);
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSetMigrationDowntime(priv->mon, downtime);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        qemuDomainObjExitMonitor(driver, vm);

        if (ret == 0)
            priv->migMaxBandwidth = bandwidth;

endjob:
        if (!qemuDomainObjEndJob(driver, vm))
            vm = NULL;
    } else {
        priv->migMaxBandwidth = bandwidth;
        ret = 0;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

typedef enum {
    VIR_DISK_CHAIN_NO_ACCESS,
    VIR_DISK_CHAIN_READ_ONLY,
    VIR_DISK_CHAIN_READ_WRITE,
} qemuDomainDiskChainMode;

/* Several operations end up adding or removing a single element of a
 * disk backing file chain; this helper function ensures that the lock
 * manager, cgroup device controller, and security manager labelling
 * are all aware of each new file before it is added to a chain, and
 * can revoke access to a file no longer needed in a chain.  */
static int
qemuDomainPrepareDiskChainElement(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virDomainDiskDefPtr disk,
                                  const char *file,
                                  qemuDomainDiskChainMode mode)
{
    /* The easiest way to label a single file with the same
     * permissions it would have as if part of the disk chain is to
     * temporarily modify the disk in place.  */
    char *origsrc = disk->src;
    int origformat = disk->format;
    virStorageFileMetadataPtr origchain = disk->backingChain;
    bool origreadonly = disk->readonly;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    disk->src = (char *) file; /* casting away const is safe here */
    disk->format = VIR_STORAGE_FILE_RAW;
    disk->backingChain = NULL;
    disk->readonly = mode == VIR_DISK_CHAIN_READ_ONLY;

    if (mode == VIR_DISK_CHAIN_NO_ACCESS) {
        if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                                vm->def, disk) < 0)
            VIR_WARN("Unable to restore security label on %s", disk->src);
        if (qemuTeardownDiskCgroup(vm, disk) < 0)
            VIR_WARN("Failed to teardown cgroup for disk path %s", disk->src);
        if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
            VIR_WARN("Unable to release lock on %s", disk->src);
    } else if (virDomainLockDiskAttach(driver->lockManager, cfg->uri,
                                       vm, disk) < 0 ||
               qemuSetupDiskCgroup(vm, disk) < 0 ||
               virSecurityManagerSetImageLabel(driver->securityManager,
                                               vm->def, disk) < 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    disk->src = origsrc;
    disk->format = origformat;
    disk->backingChain = origchain;
    disk->readonly = origreadonly;
    virObjectUnref(cfg);
    return ret;
}


static int
qemuDomainSnapshotFSFreeze(virDomainObjPtr vm) {
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int freezed;

    if (priv->agentError) {
        virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                       _("QEMU guest agent is not "
                         "available due to an error"));
        return -1;
    }
    if (!priv->agent) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("QEMU guest agent is not configured"));
        return -1;
    }

    qemuDomainObjEnterAgent(vm);
    freezed = qemuAgentFSFreeze(priv->agent);
    qemuDomainObjExitAgent(vm);

    return freezed;
}

static int
qemuDomainSnapshotFSThaw(virDomainObjPtr vm, bool report)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int thawed;
    virErrorPtr err = NULL;

    if (priv->agentError) {
        if (report)
            virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                           _("QEMU guest agent is not "
                             "available due to an error"));
        return -1;
    }
    if (!priv->agent) {
        if (report)
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("QEMU guest agent is not configured"));
        return -1;
    }

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
        defdisk = snap->def->dom->disks[snapdisk->index];
        if (snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            continue;

        if (!snapdisk->format)
            snapdisk->format = VIR_STORAGE_FILE_QCOW2;

        /* creates cmd line args: qemu-img create -f qcow2 -o */
        if (!(cmd = virCommandNewArgList(qemuImgPath,
                                         "create",
                                         "-f",
                                         virStorageFileFormatTypeToString(snapdisk->format),
                                         "-o",
                                         NULL)))
            goto cleanup;

        if (defdisk->format > 0) {
            /* adds cmd line arg: backing_file=/path/to/backing/file,backing_fmd=format */
            virCommandAddArgFormat(cmd, "backing_file=%s,backing_fmt=%s",
                                   defdisk->src,
                                   virStorageFileFormatTypeToString(defdisk->format));
        } else {
            if (!cfg->allowDiskFormatProbing) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown image format of '%s' and "
                                 "format probing is disabled"),
                               defdisk->src);
                goto cleanup;
            }

            /* adds cmd line arg: backing_file=/path/to/backing/file */
            virCommandAddArgFormat(cmd, "backing_file=%s", defdisk->src);
        }

        /* adds cmd line args: /path/to/target/file */
        virCommandAddArg(cmd, snapdisk->file);

        /* If the target does not exist, we're going to create it possibly */
        if (!virFileExists(snapdisk->file))
            ignore_value(virBitmapSetBit(created, i));

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        virCommandFree(cmd);
        cmd = NULL;
    }

    /* update disk definitions */
    for (i = 0; i < snap->def->ndisks; i++) {
        snapdisk = &(snap->def->disks[i]);
        defdisk = vm->def->disks[snapdisk->index];

        if (snapdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            VIR_FREE(defdisk->src);
            if (VIR_STRDUP(defdisk->src, snapdisk->file) < 0) {
                /* we cannot rollback here in a sane way */
                goto cleanup;
            }
            defdisk->format = snapdisk->format;
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
            if (unlink(snapdisk->file) < 0)
                VIR_WARN("Failed to remove snapshot image '%s'",
                         snapdisk->file);
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
                                       virDomainObjPtr *vmptr,
                                       virDomainSnapshotObjPtr snap,
                                       unsigned int flags)
{
    virDomainObjPtr vm = *vmptr;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainEventPtr event = NULL;
    bool resume = false;
    int ret = -1;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        return -1;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        /* savevm monitor command pauses the domain emitting an event which
         * confuses libvirt since it's not notified when qemu resumes the
         * domain. Thus we stop and start CPUs ourselves.
         */
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SAVE,
                                QEMU_ASYNC_JOB_NONE) < 0)
            goto cleanup;

        resume = true;
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto cleanup;
        }
    }

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorCreateSnapshot(priv->mon, snap->def->name);
    qemuDomainObjExitMonitor(driver, vm);
    if (ret < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        /* We already filtered the _HALT flag for persistent domains
         * only, so this end job never drops the last reference.  */
        ignore_value(qemuDomainObjEndJob(driver, vm));
        resume = false;
        vm = NULL;
    }

cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm, conn,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_NONE) < 0) {
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        if (virGetLastError() == NULL) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }
    }

endjob:
    if (vm && !qemuDomainObjEndJob(driver, vm)) {
        /* Only possible if a transient vm quit while our locks were down,
         * in which case we don't want to save snapshot metadata.  */
        *vmptr = NULL;
        ret = -1;
    }

    if (event)
        qemuDomainEventQueue(driver, event);

    return ret;
}

static int
qemuDomainSnapshotPrepare(virDomainObjPtr vm, virDomainSnapshotDefPtr def,
                          unsigned int *flags)
{
    int ret = -1;
    size_t i;
    bool active = virDomainObjIsActive(vm);
    struct stat st;
    bool reuse = (*flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    bool atomic = (*flags & VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC) != 0;
    bool found_internal = false;
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

        switch (disk->snapshot) {
        case VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL:
            if (def->state != VIR_DOMAIN_DISK_SNAPSHOT &&
                dom_disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK &&
                (dom_disk->protocol == VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG ||
                 dom_disk->protocol == VIR_DOMAIN_DISK_PROTOCOL_RBD)) {
                break;
            }
            if (vm->def->disks[i]->format > 0 &&
                vm->def->disks[i]->format != VIR_STORAGE_FILE_QCOW2) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("internal snapshot for disk %s unsupported "
                                 "for storage type %s"),
                               disk->name,
                               virStorageFileFormatTypeToString(
                                   vm->def->disks[i]->format));
                goto cleanup;
            }
            if (def->state == VIR_DOMAIN_DISK_SNAPSHOT && active) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("active qemu domains require external disk "
                                 "snapshots; disk %s requested internal"),
                               disk->name);
                goto cleanup;
            }
            found_internal = true;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL:
            if (!disk->format) {
                disk->format = VIR_STORAGE_FILE_QCOW2;
            } else if (disk->format != VIR_STORAGE_FILE_QCOW2 &&
                       disk->format != VIR_STORAGE_FILE_QED) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("external snapshot format for disk %s "
                                 "is unsupported: %s"),
                               disk->name,
                               virStorageFileFormatTypeToString(disk->format));
                goto cleanup;
            }
            if (stat(disk->file, &st) < 0) {
                if (errno != ENOENT) {
                    virReportSystemError(errno,
                                         _("unable to stat for disk %s: %s"),
                                         disk->name, disk->file);
                    goto cleanup;
                } else if (reuse) {
                    virReportSystemError(errno,
                                         _("missing existing file for disk %s: %s"),
                                         disk->name, disk->file);
                    goto cleanup;
                }
            } else if (!S_ISBLK(st.st_mode) && st.st_size && !reuse) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("external snapshot file for disk %s already "
                                 "exists and is not a block device: %s"),
                               disk->name, disk->file);
                goto cleanup;
            }
            external++;
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_NONE:
            break;

        case VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT:
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected code path"));
            goto cleanup;
        }
    }

    /* internal snapshot requires a disk image to store the memory image to */
    if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL &&
        !found_internal) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("internal checkpoints require at least "
                         "one disk to be selected for snapshot"));
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
    if (found_internal && external) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("mixing internal and external snapshots is not "
                         "supported yet"));
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
                                         bool reuse)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *device = NULL;
    char *source = NULL;
    int format = snap->format;
    const char *formatStr = NULL;
    char *persistSource = NULL;
    int ret = -1;
    int fd = -1;
    bool need_unlink = false;

    if (snap->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected code path"));
        return -1;
    }

    if (virAsprintf(&device, "drive-%s", disk->info.alias) < 0 ||
        VIR_STRDUP(source, snap->file) < 0 ||
        (persistDisk && VIR_STRDUP(persistSource, source) < 0))
        goto cleanup;

    /* create the stub file and set selinux labels; manipulate disk in
     * place, in a way that can be reverted on failure. */
    if (!reuse) {
        fd = qemuOpenFile(driver, vm, source, O_WRONLY | O_TRUNC | O_CREAT,
                          &need_unlink, NULL);
        if (fd < 0)
            goto cleanup;
        VIR_FORCE_CLOSE(fd);
    }

    /* XXX Here, we know we are about to alter disk->backingChain if
     * successful, so we nuke the existing chain so that future
     * commands will recompute it.  Better would be storing the chain
     * ourselves rather than reprobing, but this requires modifying
     * domain_conf and our XML to fully track the chain across
     * libvirtd restarts.  */
    virStorageFileFreeMetadata(disk->backingChain);
    disk->backingChain = NULL;

    if (qemuDomainPrepareDiskChainElement(driver, vm, disk, source,
                                          VIR_DISK_CHAIN_READ_WRITE) < 0) {
        qemuDomainPrepareDiskChainElement(driver, vm, disk, source,
                                          VIR_DISK_CHAIN_NO_ACCESS);
        goto cleanup;
    }

    /* create the actual snapshot */
    if (snap->format)
        formatStr = virStorageFileFormatTypeToString(snap->format);
    ret = qemuMonitorDiskSnapshot(priv->mon, actions, device, source,
                                  formatStr, reuse);
    virDomainAuditDisk(vm, disk->src, source, "snapshot", ret >= 0);
    if (ret < 0)
        goto cleanup;

    /* Update vm in place to match changes.  */
    need_unlink = false;
    VIR_FREE(disk->src);
    disk->src = source;
    source = NULL;
    disk->format = format;
    if (persistDisk) {
        VIR_FREE(persistDisk->src);
        persistDisk->src = persistSource;
        persistSource = NULL;
        persistDisk->format = format;
    }

cleanup:
    if (need_unlink && unlink(source))
        VIR_WARN("unable to unlink just-created %s", source);
    VIR_FREE(device);
    VIR_FREE(source);
    VIR_FREE(persistSource);
    return ret;
}

/* The domain is expected to hold monitor lock.  This is the
 * counterpart to qemuDomainSnapshotCreateSingleDiskActive, called
 * only on a failed transaction. */
static void
qemuDomainSnapshotUndoSingleDiskActive(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainDiskDefPtr origdisk,
                                       virDomainDiskDefPtr disk,
                                       virDomainDiskDefPtr persistDisk,
                                       bool need_unlink)
{
    char *source = NULL;
    char *persistSource = NULL;
    struct stat st;

    if (VIR_STRDUP(source, origdisk->src) < 0 ||
        (persistDisk && VIR_STRDUP(persistSource, source) < 0))
        goto cleanup;

    qemuDomainPrepareDiskChainElement(driver, vm, disk, disk->src,
                                      VIR_DISK_CHAIN_NO_ACCESS);
    if (need_unlink && stat(disk->src, &st) == 0 &&
        S_ISREG(st.st_mode) && unlink(disk->src) < 0)
        VIR_WARN("Unable to remove just-created %s", disk->src);

    /* Update vm in place to match changes.  */
    VIR_FREE(disk->src);
    disk->src = source;
    source = NULL;
    disk->format = origdisk->format;
    if (persistDisk) {
        VIR_FREE(persistDisk->src);
        persistDisk->src = persistSource;
        persistSource = NULL;
        persistDisk->format = origdisk->format;
    }

cleanup:
    VIR_FREE(source);
    VIR_FREE(persistSource);
}

/* The domain is expected to be locked and active. */
static int
qemuDomainSnapshotCreateDiskActive(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainSnapshotObjPtr snap,
                                   unsigned int flags,
                                   enum qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virJSONValuePtr actions = NULL;
    int ret = -1;
    size_t i;
    bool persist = false;
    bool reuse = (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT) != 0;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_TRANSACTION)) {
        if (!(actions = virJSONValueNewArray()))
            goto cleanup;
    } else if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DISK_SNAPSHOT)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("live disk snapshot not supported with this "
                         "QEMU binary"));
        goto cleanup;
    }

    /* No way to roll back if first disk succeeds but later disks
     * fail, unless we have transaction support.
     * Based on earlier qemuDomainSnapshotPrepare, all
     * disks in this list are now either SNAPSHOT_NO, or
     * SNAPSHOT_EXTERNAL with a valid file name and qcow2 format.  */
    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    for (i = 0; i < snap->def->ndisks; i++) {
        virDomainDiskDefPtr persistDisk = NULL;

        if (snap->def->disks[i].snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)
            continue;
        if (vm->newDef) {
            int indx = virDomainDiskIndexByName(vm->newDef,
                                                vm->def->disks[i]->dst,
                                                false);
            if (indx >= 0) {
                persistDisk = vm->newDef->disks[indx];
                persist = true;
            }
        }

        ret = qemuDomainSnapshotCreateSingleDiskActive(driver, vm,
                                                       &snap->def->disks[i],
                                                       vm->def->disks[i],
                                                       persistDisk, actions,
                                                       reuse);
        if (ret < 0)
            break;
    }
    if (actions) {
        if (ret == 0)
            ret = qemuMonitorTransaction(priv->mon, actions);
        virJSONValueFree(actions);
        if (ret < 0) {
            /* Transaction failed; undo the changes to vm.  */
            bool need_unlink = !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT);
            while (i-- > 0) {
                virDomainDiskDefPtr persistDisk = NULL;

                if (snap->def->disks[i].snapshot ==
                    VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)
                    continue;
                if (vm->newDef) {
                    int indx = virDomainDiskIndexByName(vm->newDef,
                                                        vm->def->disks[i]->dst,
                                                        false);
                    if (indx >= 0)
                        persistDisk = vm->newDef->disks[indx];
                }

                qemuDomainSnapshotUndoSingleDiskActive(driver, vm,
                                                       snap->def->dom->disks[i],
                                                       vm->def->disks[i],
                                                       persistDisk,
                                                       need_unlink);
            }
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

cleanup:

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
                                       virDomainObjPtr *vmptr,
                                       virDomainSnapshotObjPtr snap,
                                       unsigned int flags)
{
    bool resume = false;
    int ret = -1;
    virDomainObjPtr vm = *vmptr;
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

    if (qemuDomainObjBeginAsyncJob(driver, vm, QEMU_ASYNC_JOB_SNAPSHOT) < 0)
        goto cleanup;

    /* If quiesce was requested, then issue a freeze command, and a
     * counterpart thaw command, no matter what.  The command will
     * fail if the guest is paused or the guest agent is not
     * running.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE) {
        if (qemuDomainSnapshotFSFreeze(vm) < 0) {
            /* helper reported the error */
            thaw = -1;
            goto endjob;
        } else {
            thaw = 1;
        }
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
                goto endjob;

            if (!virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("guest unexpectedly quit"));
                goto endjob;
            }
        }
    }

    /* do the memory snapshot if necessary */
    if (memory) {
        /* check if migration is possible */
        if (!qemuMigrationIsAllowed(driver, vm, vm->def, false, false))
            goto endjob;

        /* allow the migration job to be cancelled or the domain to be paused */
        qemuDomainObjSetAsyncJobMask(vm, DEFAULT_JOB_MASK |
                                     JOB_MASK(QEMU_JOB_SUSPEND) |
                                     JOB_MASK(QEMU_JOB_MIGRATION_OP));

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
            goto endjob;

        if ((ret = qemuDomainSaveMemory(driver, vm, snap->def->file,
                                        xml, compressed, resume, 0,
                                        QEMU_ASYNC_JOB_SNAPSHOT)) < 0)
            goto endjob;

        /* the memory image was created, remove it on errors */
        memory_unlink = true;

        /* forbid any further manipulation */
        qemuDomainObjSetAsyncJobMask(vm, DEFAULT_JOB_MASK);
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
        goto endjob;

    /* the snapshot is complete now */
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) {
        virDomainEventPtr event;

        event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT, 0);
        virDomainAuditStop(vm, "from-snapshot");
        /* We already filtered the _HALT flag for persistent domains
         * only, so this end job never drops the last reference.  */
        ignore_value(qemuDomainObjEndAsyncJob(driver, vm));
        resume = false;
        thaw = 0;
        vm = NULL;
        if (event)
            qemuDomainEventQueue(driver, event);
    } else if (memory && pmsuspended) {
        /* qemu 1.3 is unable to save a domain in pm-suspended (S3)
         * state; so we must emit an event stating that it was
         * converted to paused.  */
        virDomainEventPtr event;

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
        event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT);
        if (event)
            qemuDomainEventQueue(driver, event);
    }

    ret = 0;

endjob:
    if (resume && vm && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm, conn,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_SNAPSHOT) < 0) {
        virDomainEventPtr event = NULL;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        if (event)
            qemuDomainEventQueue(driver, event);
        if (virGetLastError() == NULL) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after snapshot failed"));
        }

        ret = -1;
        goto cleanup;
    }
    if (vm && thaw != 0 &&
        qemuDomainSnapshotFSThaw(vm, thaw > 0) < 0) {
        /* helper reported the error, if it was needed */
        if (thaw > 0)
            ret = -1;
    }
    if (vm && !qemuDomainObjEndAsyncJob(driver, vm)) {
        /* Only possible if a transient vm quit while our locks were down,
         * in which case we don't want to save snapshot metadata.
         */
        *vmptr = NULL;
        ret = -1;
    }

cleanup:
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
    int align_match = true;
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

    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE) &&
        !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("quiesce requires disk-only"));
        return NULL;
    }

    if ((redefine && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) ||
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA))
        update_current = false;
    if (redefine)
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainSnapshotCreateXMLEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuProcessAutoDestroyActive(driver, vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is marked for auto destroy"));
        goto cleanup;
    }
    if (virDomainHasDiskMirror(vm)) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE, "%s",
                       _("domain has active block copy job"));
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
                                                QEMU_EXPECTED_VIRT_TYPES,
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

    if (redefine) {
        if (!virDomainSnapshotRedefinePrep(domain, vm, &def, &snap,
                                           &update_current, flags) < 0)
            goto cleanup;
    } else {
        /* Easiest way to clone inactive portion of vm->def is via
         * conversion in and back out of xml.  */
        if (!(xml = qemuDomainDefFormatLive(driver, vm->def, true, true)) ||
            !(def->dom = virDomainDefParseString(xml, caps, driver->xmlopt,
                                                 QEMU_EXPECTED_VIRT_TYPES,
                                                 VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

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
            def->memory = (def->state == VIR_DOMAIN_SHUTOFF ?
                           VIR_DOMAIN_SNAPSHOT_LOCATION_NONE :
                           VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL);
        }
        if (virDomainSnapshotAlignDisks(def, align_location,
                                        align_match) < 0 ||
            qemuDomainSnapshotPrepare(vm, def, &flags) < 0)
            goto cleanup;
    }

    if (!snap) {
        if (!(snap = virDomainSnapshotAssignDef(vm->snapshots, def)))
            goto cleanup;

        def = NULL;
    }

    if (update_current)
        snap->def->current = true;
    if (vm->current_snapshot) {
        if (!redefine &&
            VIR_STRDUP(snap->def->parent, vm->current_snapshot->def->name) < 0)
                goto cleanup;
        if (update_current) {
            vm->current_snapshot->def->current = false;
            if (qemuDomainSnapshotWriteMetadata(vm, vm->current_snapshot,
                                                cfg->snapshotDir) < 0)
                goto cleanup;
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
                                                       &vm, snap, flags) < 0)
                goto cleanup;
        } else {
            /* internal checkpoint */
            if (qemuDomainSnapshotCreateActiveInternal(domain->conn, driver,
                                                       &vm, snap, flags) < 0)
                goto cleanup;
        }
    } else {
        /* inactive; qemuDomainSnapshotPrepare guaranteed that we
         * aren't mixing internal and external, and altered flags to
         * contain DISK_ONLY if there is an external disk.  */
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
            bool reuse = !!(flags & VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT);

            if (qemuDomainSnapshotCreateInactiveExternal(driver, vm, snap,
                                                         reuse) < 0)
                goto cleanup;
        } else {
            if (qemuDomainSnapshotCreateInactiveInternal(driver, vm, snap) < 0)
                goto cleanup;
        }
    }

    /* If we fail after this point, there's not a whole lot we can
     * do; we've successfully taken the snapshot, and we are now running
     * on it, so we have to go forward the best we can
     */
    snapshot = virGetDomainSnapshot(domain, snap->def->name);

cleanup:
    if (vm) {
        if (snapshot && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA)) {
            if (qemuDomainSnapshotWriteMetadata(vm, snap,
                                                cfg->snapshotDir) < 0) {
                /* if writing of metadata fails, error out rather than trying
                 * to silently carry on  without completing the snapshot */
                virDomainSnapshotFree(snapshot);
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
        virObjectUnlock(vm);
    }
    virDomainSnapshotDefFree(def);
    VIR_FREE(xml);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return snapshot;
}

static int qemuDomainSnapshotListNames(virDomainPtr domain, char **names,
                                       int nameslen,
                                       unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainSnapshotListNamesEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    n = virDomainSnapshotObjListGetNames(vm->snapshots, NULL, names, nameslen,
                                         flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return n;
}

static int qemuDomainSnapshotNum(virDomainPtr domain,
                                 unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainSnapshotNumEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    n = virDomainSnapshotObjListNum(vm->snapshots, NULL, flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return n;
}

static int
qemuDomainListAllSnapshots(virDomainPtr domain, virDomainSnapshotPtr **snaps,
                           unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainListAllSnapshotsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    n = virDomainListSnapshots(vm->snapshots, NULL, domain, snaps, flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        goto cleanup;

    if (virDomainSnapshotListChildrenNamesEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainSnapshotObjListGetNames(vm->snapshots, snap, names, nameslen,
                                         flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        goto cleanup;

    if (virDomainSnapshotNumChildrenEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainSnapshotObjListNum(vm->snapshots, snap, flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        goto cleanup;

    if (virDomainSnapshotListAllChildrenEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainListSnapshots(vm->snapshots, snap, snapshot->domain, snaps,
                               flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return n;
}

static virDomainSnapshotPtr qemuDomainSnapshotLookupByName(virDomainPtr domain,
                                                           const char *name,
                                                           unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainSnapshotLookupByNameEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromName(vm, name)))
        goto cleanup;

    snapshot = virGetDomainSnapshot(domain, snap->def->name);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return snapshot;
}

static int qemuDomainHasCurrentSnapshot(virDomainPtr domain,
                                        unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainHasCurrentSnapshotEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    ret = (vm->current_snapshot != NULL);

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        goto cleanup;

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
    if (vm)
        virObjectUnlock(vm);
    return parent;
}

static virDomainSnapshotPtr qemuDomainSnapshotCurrent(virDomainPtr domain,
                                                      unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = qemuDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainSnapshotCurrentEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->current_snapshot) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT, "%s",
                       _("the domain does not have a current snapshot"));
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, vm->current_snapshot->def->name);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return snapshot;
}

static char *qemuDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                                          unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    char *xml = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virCheckFlags(VIR_DOMAIN_XML_SECURE, NULL);

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        goto cleanup;

    if (virDomainSnapshotGetXMLDescEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    virUUIDFormat(snapshot->domain->uuid, uuidstr);

    xml = virDomainSnapshotDefFormat(uuidstr, snap->def, flags, 0);

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        goto cleanup;

    if (virDomainSnapshotIsCurrentEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    ret = (vm->current_snapshot &&
           STREQ(snapshot->name, vm->current_snapshot->def->name));

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        goto cleanup;

    if (virDomainSnapshotHasMetadataEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    /* XXX Someday, we should recognize internal snapshots in qcow2
     * images that are not tied to a libvirt snapshot; if we ever do
     * that, then we would have a reason to return 0 here.  */
    ret = 1;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

static int qemuDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                                      unsigned int flags)
{
    virQEMUDriverPtr driver = snapshot->domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainEventPtr event = NULL;
    virDomainEventPtr event2 = NULL;
    int detail;
    qemuDomainObjPrivatePtr priv;
    int rc;
    virDomainDefPtr config = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

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

    if (!(vm = qemuDomObjFromSnapshot(snapshot)))
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (virDomainRevertToSnapshotEnsureACL(snapshot->domain->conn, vm->def) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainHasDiskMirror(vm)) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE, "%s",
                       _("domain has active block copy job"));
        goto cleanup;
    }

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    if (!vm->persistent &&
        snap->def->state != VIR_DOMAIN_RUNNING &&
        snap->def->state != VIR_DOMAIN_PAUSED &&
        (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("transient domain needs to request run or pause "
                         "to revert to inactive snapshot"));
        goto cleanup;
    }
    if (snap->def->state == VIR_DOMAIN_DISK_SNAPSHOT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("revert to external disk snapshot not supported "
                         "yet"));
        goto cleanup;
    }
    if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
        if (!snap->def->dom) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY,
                           _("snapshot '%s' lacks domain '%s' rollback info"),
                           snap->def->name, vm->def->name);
            goto cleanup;
        }
        if (virDomainObjIsActive(vm) &&
            !(snap->def->state == VIR_DOMAIN_RUNNING
              || snap->def->state == VIR_DOMAIN_PAUSED) &&
            (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                      VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                           _("must respawn qemu to start inactive snapshot"));
            goto cleanup;
        }
    }


    if (vm->current_snapshot) {
        vm->current_snapshot->def->current = false;
        if (qemuDomainSnapshotWriteMetadata(vm, vm->current_snapshot,
                                            cfg->snapshotDir) < 0)
            goto cleanup;
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
            goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (snap->def->state == VIR_DOMAIN_RUNNING
        || snap->def->state == VIR_DOMAIN_PAUSED) {
        /* Transitions 2, 3, 5, 6, 8, 9 */
        bool was_running = false;
        bool was_stopped = false;

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
                event = virDomainEventNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_STOPPED,
                                                 detail);
                if (event)
                    qemuDomainEventQueue(driver, event);
                goto load;
            }

            priv = vm->privateData;
            if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
                /* Transitions 5, 6 */
                was_running = true;
                if (qemuProcessStopCPUs(driver, vm,
                                        VIR_DOMAIN_PAUSED_FROM_SNAPSHOT,
                                        QEMU_ASYNC_JOB_NONE) < 0)
                    goto endjob;
                /* Create an event now in case the restore fails, so
                 * that user will be alerted that they are now paused.
                 * If restore later succeeds, we might replace this. */
                detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
                event = virDomainEventNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_SUSPENDED,
                                                 detail);
                if (!virDomainObjIsActive(vm)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("guest unexpectedly quit"));
                    goto endjob;
                }
            }
            qemuDomainObjEnterMonitor(driver, vm);
            rc = qemuMonitorLoadSnapshot(priv->mon, snap->def->name);
            qemuDomainObjExitMonitor(driver, vm);
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

            rc = qemuProcessStart(snapshot->domain->conn,
                                  driver, vm, NULL, -1, NULL, snap,
                                  VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                  VIR_QEMU_PROCESS_START_PAUSED);
            virDomainAuditStart(vm, "from-snapshot", rc >= 0);
            detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
            event = virDomainEventNewFromObj(vm,
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
                event2 = virDomainEventNewFromObj(vm,
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
                                      QEMU_ASYNC_JOB_NONE);
            if (rc < 0)
                goto endjob;
            virDomainEventFree(event);
            event = NULL;
            if (was_stopped) {
                /* Transition 2 */
                detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
                event = virDomainEventNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_STARTED,
                                                 detail);
            } else if (was_running) {
                /* Transition 8 */
                detail = VIR_DOMAIN_EVENT_RESUMED;
                event = virDomainEventNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_RESUMED,
                                                 detail);
            }
        }
    } else {
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
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             detail);
        }

        if (qemuDomainSnapshotRevertInactive(driver, vm, snap) < 0) {
            if (!vm->persistent) {
                if (qemuDomainObjEndJob(driver, vm))
                    qemuDomainRemoveInactive(driver, vm);
                vm = NULL;
                goto cleanup;
            }
            goto endjob;
        }
        if (config)
            virDomainObjAssignDef(vm, config, false, NULL);

        if (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                     VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) {
            /* Flush first event, now do transition 2 or 3 */
            bool paused = (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED) != 0;
            unsigned int start_flags = 0;

            start_flags |= paused ? VIR_QEMU_PROCESS_START_PAUSED : 0;

            if (event)
                qemuDomainEventQueue(driver, event);
            rc = qemuProcessStart(snapshot->domain->conn,
                                  driver, vm, NULL, -1, NULL, NULL,
                                  VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                  start_flags);
            virDomainAuditStart(vm, "from-snapshot", rc >= 0);
            if (rc < 0) {
                if (!vm->persistent) {
                    if (qemuDomainObjEndJob(driver, vm))
                        qemuDomainRemoveInactive(driver, vm);
                    vm = NULL;
                    goto cleanup;
                }
                goto endjob;
            }
            detail = VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT;
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STARTED,
                                             detail);
            if (paused) {
                detail = VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT;
                event2 = virDomainEventNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  detail);
            }
        }
    }

    ret = 0;

endjob:
    if (vm && !qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm && ret == 0) {
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
        if (event2)
            qemuDomainEventQueue(driver, event2);
    }
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);

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

    if (rep->err < 0) {
        return;
    }

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


static int qemuDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
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

    if (!(snap = qemuSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    if (!metadata_only) {
        if (!(flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) &&
            virDomainSnapshotIsExternal(snap))
            external++;
        if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN)
            virDomainSnapshotForEachDescendant(snap,
                                               qemuDomainSnapshotCountExternal,
                                               &external);
        if (external) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("deletion of %d external disk snapshots not "
                             "supported yet"), external);
            goto cleanup;
        }
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

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
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    qemuDomainObjTaint(driver, vm, VIR_DOMAIN_TAINT_CUSTOM_MONITOR, -1);

    hmp = !!(flags & VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP);

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorArbitraryCommand(priv->mon, cmd, result, hmp);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm)) {
        vm = NULL;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    if (qemuDomainAssignAddresses(def, qemuCaps, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    def = NULL;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0) {
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
        goto cleanup;
    }

    if (qemuProcessAttach(conn, driver, vm, pid,
                          pidfile, monConfig, monJSON) < 0) {
        if (qemuDomainObjEndJob(driver, vm))
            qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
        monConfig = NULL;
        goto cleanup;
    }

    monConfig = NULL;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    virDomainDefFree(def);
    virDomainChrSourceDefFree(monConfig);
    if (vm)
        virObjectUnlock(vm);
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
                       NULLSTR(dev_name));
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
    if (vm)
        virObjectUnlock(vm);
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
                STREQ(name, vm->def->channels[i]->target.name))
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
                       NULLSTR(name));
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
    if (vm)
        virObjectUnlock(vm);
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

    if (disk->src) {
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
qemuDomainBlockPivot(virConnectPtr conn,
                     virQEMUDriverPtr driver, virDomainObjPtr vm,
                     const char *device, virDomainDiskDefPtr disk)
{
    int ret = -1, rc;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainBlockJobInfo info;
    const char *format = virStorageFileFormatTypeToString(disk->mirrorFormat);
    bool resume = false;
    char *oldsrc = NULL;
    int oldformat;
    virStorageFileMetadataPtr oldchain = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    /* Probe the status, if needed.  */
    if (!disk->mirroring) {
        qemuDomainObjEnterMonitor(driver, vm);
        rc = qemuMonitorBlockJob(priv->mon, device, NULL, 0, &info,
                                  BLOCK_JOB_INFO, true);
        qemuDomainObjExitMonitor(driver, vm);
        if (rc < 0)
            goto cleanup;
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain is not running"));
            goto cleanup;
        }
        if (rc == 1 && info.cur == info.end &&
            info.type == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY)
            disk->mirroring = true;
    }

    if (!disk->mirroring) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE,
                       _("disk '%s' not ready for pivot yet"),
                       disk->dst);
        goto cleanup;
    }

    /* If we are using the older 'drive-reopen', we want to make sure
     * that management apps can tell whether the command succeeded,
     * even if libvirtd is restarted at the wrong time.  To accomplish
     * that, we pause the guest before drive-reopen, and resume it
     * only when we know the outcome; if libvirtd restarts, then
     * management will see the guest still paused, and know that no
     * guest I/O has caused the source and mirror to diverge.  XXX
     * With the newer 'block-job-complete', we need to use a
     * persistent bitmap to make things safe; so for now, we just
     * blindly pause the guest.  */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SAVE,
                                QEMU_ASYNC_JOB_NONE) < 0)
            goto cleanup;

        resume = true;
        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto cleanup;
        }
    }

    /* We previously labeled only the top-level image; but if the
     * image includes a relative backing file, the pivot may result in
     * qemu needing to open the entire backing chain, so we need to
     * label the entire chain.  This action is safe even if the
     * backing chain has already been labeled; but only necessary when
     * we know for sure that there is a backing chain.  */
    oldsrc = disk->src;
    oldformat = disk->format;
    oldchain = disk->backingChain;
    disk->src = disk->mirror;
    disk->format = disk->mirrorFormat;
    disk->backingChain = NULL;
    if (qemuDomainDetermineDiskChain(driver, disk, false) < 0) {
        disk->src = oldsrc;
        disk->format = oldformat;
        disk->backingChain = oldchain;
        goto cleanup;
    }
    if (disk->mirrorFormat && disk->mirrorFormat != VIR_STORAGE_FILE_RAW &&
        (virDomainLockDiskAttach(driver->lockManager, cfg->uri,
                                 vm, disk) < 0 ||
         qemuSetupDiskCgroup(vm, disk) < 0 ||
         virSecurityManagerSetImageLabel(driver->securityManager, vm->def,
                                         disk) < 0)) {
        disk->src = oldsrc;
        disk->format = oldformat;
        disk->backingChain = oldchain;
        goto cleanup;
    }

    /* Attempt the pivot.  */
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDrivePivot(priv->mon, device, disk->mirror, format);
    qemuDomainObjExitMonitor(driver, vm);

    if (ret == 0) {
        /* XXX We want to revoke security labels and disk lease, as
         * well as audit that revocation, before dropping the original
         * source.  But it gets tricky if both source and mirror share
         * common backing files (we want to only revoke the non-shared
         * portion of the chain, and is made more difficult by the
         * fact that we aren't tracking the full chain ourselves; so
         * for now, we leak the access to the original.  */
        VIR_FREE(oldsrc);
        virStorageFileFreeMetadata(oldchain);
        disk->mirror = NULL;
    } else {
        /* On failure, qemu abandons the mirror, and reverts back to
         * the source disk (RHEL 6.3 has a bug where the revert could
         * cause catastrophic failure in qemu, but we don't need to
         * worry about it here as it is not an upstream qemu problem.  */
        /* XXX should we be parsing the exact qemu error, or calling
         * 'query-block', to see what state we really got left in
         * before killing the mirroring job?  And just as on the
         * success case, there's security labeling to worry about.  */
        disk->src = oldsrc;
        disk->format = oldformat;
        virStorageFileFreeMetadata(disk->backingChain);
        disk->backingChain = oldchain;
        VIR_FREE(disk->mirror);
    }
    disk->mirrorFormat = VIR_STORAGE_FILE_NONE;
    disk->mirroring = false;

cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm, conn,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_NONE) < 0) {
        virDomainEventPtr event = NULL;
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
        if (event)
            qemuDomainEventQueue(driver, event);
        if (virGetLastError() == NULL) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("resuming after drive-reopen failed"));
        }
    }
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainBlockJobImpl(virDomainObjPtr vm,
                       virConnectPtr conn,
                       const char *path, const char *base,
                       unsigned long bandwidth, virDomainBlockJobInfoPtr info,
                       int mode, unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuDomainObjPrivatePtr priv;
    char *device = NULL;
    int ret = -1;
    bool async = false;
    virDomainEventPtr event = NULL;
    int idx;
    virDomainDiskDefPtr disk;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_ASYNC)) {
        async = true;
    } else if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_SYNC)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block jobs not supported with this QEMU binary"));
        goto cleanup;
    } else if (base) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("partial block pull not supported with this "
                         "QEMU binary"));
        goto cleanup;
    } else if (mode == BLOCK_JOB_PULL && bandwidth) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("setting bandwidth at start of block pull not "
                         "supported with this QEMU binary"));
        goto cleanup;
    }

    device = qemuDiskPathToAlias(vm, path, &idx);
    if (!device)
        goto cleanup;
    disk = vm->def->disks[idx];

    if (mode == BLOCK_JOB_PULL && disk->mirror) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE,
                       _("disk '%s' already in active block copy job"),
                       disk->dst);
        goto cleanup;
    }
    if (mode == BLOCK_JOB_ABORT &&
        (flags & VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT) &&
        !(async && disk->mirror)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("pivot of disk '%s' requires an active copy job"),
                       disk->dst);
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    if (disk->mirror && mode == BLOCK_JOB_ABORT &&
        (flags & VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT)) {
        ret = qemuDomainBlockPivot(conn, driver, vm, device, disk);
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    /* XXX - libvirt should really be tracking the backing file chain
     * itself, and validating that base is on the chain, rather than
     * relying on qemu to do this.  */
    ret = qemuMonitorBlockJob(priv->mon, device, base, bandwidth, info, mode,
                              async);
    qemuDomainObjExitMonitor(driver, vm);
    if (ret < 0)
        goto endjob;

    /* Snoop block copy operations, so future cancel operations can
     * avoid checking if pivot is safe.  */
    if (mode == BLOCK_JOB_INFO && ret == 1 && disk->mirror &&
        info->cur == info->end && info->type == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY)
        disk->mirroring = true;

    /* A successful block job cancelation stops any mirroring.  */
    if (mode == BLOCK_JOB_ABORT && disk->mirror) {
        /* XXX We should also revoke security labels and disk lease on
         * the mirror, and audit that fact, before dropping things.  */
        VIR_FREE(disk->mirror);
        disk->mirrorFormat = VIR_STORAGE_FILE_NONE;
        disk->mirroring = false;
    }

    /* With synchronous block cancel, we must synthesize an event, and
     * we silently ignore the ABORT_ASYNC flag.  With asynchronous
     * block cancel, the event will come from qemu, but without the
     * ABORT_ASYNC flag, we must block to guarantee synchronous
     * operation.  We do the waiting while still holding the VM job,
     * to prevent newly scheduled block jobs from confusing us.  */
    if (mode == BLOCK_JOB_ABORT) {
        if (!async) {
            int type = VIR_DOMAIN_BLOCK_JOB_TYPE_PULL;
            int status = VIR_DOMAIN_BLOCK_JOB_CANCELED;
            event = virDomainEventBlockJobNewFromObj(vm, disk->src, type,
                                                     status);
        } else if (!(flags & VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC)) {
            while (1) {
                /* Poll every 50ms */
                static struct timespec ts = { .tv_sec = 0,
                                              .tv_nsec = 50 * 1000 * 1000ull };
                virDomainBlockJobInfo dummy;

                qemuDomainObjEnterMonitor(driver, vm);
                ret = qemuMonitorBlockJob(priv->mon, device, NULL, 0, &dummy,
                                          BLOCK_JOB_INFO, async);
                qemuDomainObjExitMonitor(driver, vm);

                if (ret <= 0)
                    break;

                virObjectUnlock(vm);

                nanosleep(&ts, NULL);

                virObjectLock(vm);

                if (!virDomainObjIsActive(vm)) {
                    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                   _("domain is not running"));
                    ret = -1;
                    break;
                }
            }
        }
    }

endjob:
    if (!qemuDomainObjEndJob(driver, vm)) {
        vm = NULL;
        goto cleanup;
    }

cleanup:
    VIR_FREE(device);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    return ret;
}

static int
qemuDomainBlockJobAbort(virDomainPtr dom, const char *path, unsigned int flags)
{
    virDomainObjPtr vm;

    virCheckFlags(VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC |
                  VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockJobAbortEnsureACL(dom->conn, vm->def) < 0) {
        virObjectUnlock(vm);
        return -1;
    }

    return qemuDomainBlockJobImpl(vm, dom->conn, path, NULL, 0, NULL, BLOCK_JOB_ABORT,
                                  flags);
}

static int
qemuDomainGetBlockJobInfo(virDomainPtr dom, const char *path,
                           virDomainBlockJobInfoPtr info, unsigned int flags)
{
    virDomainObjPtr vm;
    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetBlockJobInfoEnsureACL(dom->conn, vm->def) < 0) {
        virObjectUnlock(vm);
        return -1;
    }

    return qemuDomainBlockJobImpl(vm, dom->conn, path, NULL, 0, info, BLOCK_JOB_INFO,
                                  flags);
}

static int
qemuDomainBlockJobSetSpeed(virDomainPtr dom, const char *path,
                           unsigned long bandwidth, unsigned int flags)
{
    virDomainObjPtr vm;
    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockJobSetSpeedEnsureACL(dom->conn, vm->def) < 0) {
        virObjectUnlock(vm);
        return -1;
    }

    return qemuDomainBlockJobImpl(vm, dom->conn, path, NULL, bandwidth, NULL,
                                  BLOCK_JOB_SPEED, flags);
}

static int
qemuDomainBlockCopy(virDomainObjPtr vm,
                    virConnectPtr conn,
                    const char *path,
                    const char *dest, const char *format,
                    unsigned long bandwidth, unsigned int flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuDomainObjPrivatePtr priv;
    char *device = NULL;
    virDomainDiskDefPtr disk;
    int ret = -1;
    int idx;
    struct stat st;
    bool need_unlink = false;
    char *mirror = NULL;
    virQEMUDriverConfigPtr cfg = NULL;

    /* Preliminaries: find the disk we are editing, sanity checks */
    virCheckFlags(VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                  VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT, -1);

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto cleanup;
    }

    device = qemuDiskPathToAlias(vm, path, &idx);
    if (!device) {
        goto cleanup;
    }
    disk = vm->def->disks[idx];
    if (disk->mirror) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE,
                       _("disk '%s' already in active block copy job"),
                       disk->dst);
        goto cleanup;
    }

    if (!(virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_MIRROR) &&
          virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_ASYNC))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block copy is not supported with this QEMU binary"));
        goto cleanup;
    }
    if (vm->persistent) {
        /* XXX if qemu ever lets us start a new domain with mirroring
         * already active, we can relax this; but for now, the risk of
         * 'managedsave' due to libvirt-guests means we can't risk
         * this on persistent domains.  */
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not transient"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }
    if (qemuDomainDetermineDiskChain(driver, disk, false) < 0)
        goto endjob;

    if ((flags & VIR_DOMAIN_BLOCK_REBASE_SHALLOW) &&
        STREQ_NULLABLE(format, "raw") &&
        disk->backingChain->backingStore) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk '%s' has backing file, so raw shallow copy "
                         "is not possible"),
                       disk->dst);
        goto endjob;
    }

    /* Prepare the destination file.  */
    if (stat(dest, &st) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno, _("unable to stat for disk %s: %s"),
                                 disk->dst, dest);
            goto endjob;
        } else if (flags & VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT) {
            virReportSystemError(errno,
                                 _("missing destination file for disk %s: %s"),
                                 disk->dst, dest);
            goto endjob;
        }
    } else if (!S_ISBLK(st.st_mode) && st.st_size &&
               !(flags & VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("external destination file for disk %s already "
                         "exists and is not a block device: %s"),
                       disk->dst, dest);
        goto endjob;
    }

    if (!(flags & VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT)) {
        int fd = qemuOpenFile(driver, vm, dest, O_WRONLY | O_TRUNC | O_CREAT,
                              &need_unlink, NULL);
        if (fd < 0)
            goto endjob;
        VIR_FORCE_CLOSE(fd);
        if (!format)
            disk->mirrorFormat = disk->format;
    } else if (format) {
        disk->mirrorFormat = virStorageFileFormatTypeFromString(format);
        if (disk->mirrorFormat <= 0) {
            virReportError(VIR_ERR_INVALID_ARG, _("unrecognized format '%s'"),
                           format);
            goto endjob;
        }
    } else {
        /* If the user passed the REUSE_EXT flag, then either they
         * also passed the RAW flag (and format is non-NULL), or it is
         * safe for us to probe the format from the file that we will
         * be using.  */
        disk->mirrorFormat = virStorageFileProbeFormat(dest, cfg->user,
                                                       cfg->group);
    }
    if (!format && disk->mirrorFormat > 0)
        format = virStorageFileFormatTypeToString(disk->mirrorFormat);
    if (VIR_STRDUP(mirror, dest) < 0)
        goto endjob;

    if (qemuDomainPrepareDiskChainElement(driver, vm, disk, dest,
                                          VIR_DISK_CHAIN_READ_WRITE) < 0) {
        qemuDomainPrepareDiskChainElement(driver, vm, disk, dest,
                                          VIR_DISK_CHAIN_NO_ACCESS);
        goto endjob;
    }

    /* Actually start the mirroring */
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDriveMirror(priv->mon, device, dest, format, bandwidth,
                                 flags);
    virDomainAuditDisk(vm, NULL, dest, "mirror", ret >= 0);
    qemuDomainObjExitMonitor(driver, vm);
    if (ret < 0) {
        qemuDomainPrepareDiskChainElement(driver, vm, disk, dest,
                                          VIR_DISK_CHAIN_NO_ACCESS);
        goto endjob;
    }

    /* Update vm in place to match changes.  */
    need_unlink = false;
    disk->mirror = mirror;
    mirror = NULL;

endjob:
    if (need_unlink && unlink(dest))
        VIR_WARN("unable to unlink just-created %s", dest);
    if (ret < 0)
        disk->mirrorFormat = VIR_STORAGE_FILE_NONE;
    VIR_FREE(mirror);
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    VIR_FREE(device);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int
qemuDomainBlockRebase(virDomainPtr dom, const char *path, const char *base,
                      unsigned long bandwidth, unsigned int flags)
{
    virDomainObjPtr vm;

    virCheckFlags(VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                  VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                  VIR_DOMAIN_BLOCK_REBASE_COPY |
                  VIR_DOMAIN_BLOCK_REBASE_COPY_RAW, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockRebaseEnsureACL(dom->conn, vm->def) < 0) {
        virObjectUnlock(vm);
        return -1;
    }

    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY) {
        const char *format = NULL;
        if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY_RAW)
            format = "raw";
        flags &= ~(VIR_DOMAIN_BLOCK_REBASE_COPY |
                   VIR_DOMAIN_BLOCK_REBASE_COPY_RAW);
        return qemuDomainBlockCopy(vm, dom->conn, path, base, format, bandwidth, flags);
    }

    return qemuDomainBlockJobImpl(vm, dom->conn, path, base, bandwidth, NULL,
                                  BLOCK_JOB_PULL, flags);
}

static int
qemuDomainBlockPull(virDomainPtr dom, const char *path, unsigned long bandwidth,
                    unsigned int flags)
{
    virDomainObjPtr vm;
    virCheckFlags(0, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockPullEnsureACL(dom->conn, vm->def) < 0) {
        virObjectUnlock(vm);
        return -1;
    }

    return qemuDomainBlockJobImpl(vm, dom->conn, path, NULL, bandwidth, NULL,
                                  BLOCK_JOB_PULL, flags);
}


static int
qemuDomainBlockCommit(virDomainPtr dom, const char *path, const char *base,
                      const char *top, unsigned long bandwidth,
                      unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm = NULL;
    char *device = NULL;
    int ret = -1;
    int idx;
    virDomainDiskDefPtr disk = NULL;
    const char *top_canon = NULL;
    virStorageFileMetadataPtr top_meta = NULL;
    const char *top_parent = NULL;
    const char *base_canon = NULL;
    bool clean_access = false;

    virCheckFlags(VIR_DOMAIN_BLOCK_COMMIT_SHALLOW, -1);

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
    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCK_COMMIT)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("online commit not supported with this QEMU binary"));
        goto endjob;
    }

    device = qemuDiskPathToAlias(vm, path, &idx);
    if (!device)
        goto endjob;
    disk = vm->def->disks[idx];

    if (!disk->src) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk %s has no source file to be committed"),
                       disk->dst);
        goto endjob;
    }
    if (qemuDomainDetermineDiskChain(driver, disk, false) < 0)
        goto endjob;

    if (!top) {
        top_canon = disk->src;
        top_meta = disk->backingChain;
    } else if (!(top_canon = virStorageFileChainLookup(disk->backingChain,
                                                       disk->src,
                                                       top, &top_meta,
                                                       &top_parent))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find top '%s' in chain for '%s'"),
                       top, path);
        goto endjob;
    }
    if (!top_meta || !top_meta->backingStore) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("top '%s' in chain for '%s' has no backing file"),
                       top, path);
        goto endjob;
    }
    if (!base && (flags & VIR_DOMAIN_BLOCK_COMMIT_SHALLOW)) {
        base_canon = top_meta->backingStore;
    } else if (!(base_canon = virStorageFileChainLookup(top_meta, top_canon,
                                                        base, NULL, NULL))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("could not find base '%s' below '%s' in chain "
                         "for '%s'"),
                       base ? base : "(default)", top_canon, path);
        goto endjob;
    }
    /* Note that this code exploits the fact that
     * virStorageFileChainLookup guarantees a simple pointer
     * comparison will work, rather than needing full-blown STREQ.  */
    if ((flags & VIR_DOMAIN_BLOCK_COMMIT_SHALLOW) &&
        base_canon != top_meta->backingStore) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("base '%s' is not immediately below '%s' in chain "
                         "for '%s'"),
                       base, top_canon, path);
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
    if (qemuDomainPrepareDiskChainElement(driver, vm, disk, base_canon,
                                          VIR_DISK_CHAIN_READ_WRITE) < 0 ||
        (top_parent && top_parent != disk->src &&
         qemuDomainPrepareDiskChainElement(driver, vm, disk,
                                           top_parent,
                                           VIR_DISK_CHAIN_READ_WRITE) < 0))
        goto endjob;

    /* Start the commit operation.  */
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorBlockCommit(priv->mon, device, top_canon, base_canon,
                                 bandwidth);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (ret < 0 && clean_access) {
        /* Revert access to read-only, if possible.  */
        qemuDomainPrepareDiskChainElement(driver, vm, disk, base_canon,
                                          VIR_DISK_CHAIN_READ_ONLY);
        if (top_parent && top_parent != disk->src)
            qemuDomainPrepareDiskChainElement(driver, vm, disk,
                                              top_parent,
                                              VIR_DISK_CHAIN_READ_ONLY);
    }
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    VIR_FREE(device);
    if (vm)
        virObjectUnlock(vm);
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
    qemuDomainObjExitMonitor(driver, vm);
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    bool set_bytes = false;
    bool set_iops = false;
    virQEMUDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

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
                               NULL) < 0)
        return -1;

    memset(&info, 0, sizeof(info));

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainSetBlockIoTuneEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto endjob;

    if (!(device = qemuDiskPathToAlias(vm, disk, &idx)))
        goto endjob;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
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
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC)) {
            info.read_bytes_sec = param->value.ul;
            set_bytes = true;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC)) {
            info.write_bytes_sec = param->value.ul;
            set_bytes = true;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC)) {
            info.total_iops_sec = param->value.ul;
            set_iops = true;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC)) {
            info.read_iops_sec = param->value.ul;
            set_iops = true;
        } else if (STREQ(param->field,
                         VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC)) {
            info.write_iops_sec = param->value.ul;
            set_iops = true;
        }
    }

    if ((info.total_bytes_sec && info.read_bytes_sec) ||
        (info.total_bytes_sec && info.write_bytes_sec)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("total and read/write of bytes_sec cannot be set at the same time"));
        goto endjob;
    }

    if ((info.total_iops_sec && info.read_iops_sec) ||
        (info.total_iops_sec && info.write_iops_sec)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("total and read/write of iops_sec cannot be set at the same time"));
        goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_IOTUNE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block I/O throttling not supported with this "
                         "QEMU binary"));
            goto endjob;
        }

        /* If the user didn't specify bytes limits, inherit previous
         * values; likewise if the user didn't specify iops
         * limits.  */
        oldinfo = &vm->def->disks[idx]->blkdeviotune;
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
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSetBlockIoThrottle(priv->mon, device, &info);
        qemuDomainObjExitMonitor(driver, vm);
        if (ret < 0)
            goto endjob;
        vm->def->disks[idx]->blkdeviotune = info;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        sa_assert(persistentDef);
        oldinfo = &persistentDef->disks[idx]->blkdeviotune;
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
        persistentDef->disks[idx]->blkdeviotune = info;
        ret = virDomainSaveConfig(cfg->configDir, persistentDef);
        if (ret < 0) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Write to config file failed"));
            goto endjob;
        }
    }

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    VIR_FREE(device);
    if (vm)
        virObjectUnlock(vm);
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
    qemuDomainObjPrivatePtr priv;
    virDomainDefPtr persistentDef = NULL;
    virDomainBlockIoTuneInfo reply;
    char *device = NULL;
    int ret = -1;
    size_t i;
    virCapsPtr caps = NULL;

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

    if ((*nparams) == 0) {
        /* Current number of parameters supported by QEMU Block I/O Throttling */
        *nparams = QEMU_NB_BLOCK_IO_TUNE_PARAM;
        ret = 0;
        goto cleanup;
    }

    device = qemuDiskPathToAlias(vm, disk, NULL);

    if (!device) {
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        priv = vm->privateData;
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorGetBlockIoThrottle(priv->mon, device, &reply);
        qemuDomainObjExitMonitor(driver, vm);
        if (ret < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        int idx = virDomainDiskIndexByName(vm->def, disk, true);
        if (idx < 0)
            goto endjob;
        reply = persistentDef->disks[idx]->blkdeviotune;
    }

    for (i = 0; i < QEMU_NB_BLOCK_IO_TUNE_PARAM && i < *nparams; i++) {
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
        default:
            break;
        }
    }

    if (*nparams > QEMU_NB_BLOCK_IO_TUNE_PARAM)
        *nparams = QEMU_NB_BLOCK_IO_TUNE_PARAM;
    ret = 0;

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    VIR_FREE(device);
    if (vm)
        virObjectUnlock(vm);
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
    qemuDomainObjExitMonitor(driver, vm);
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
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri, caps,
                                  driver->xmlopt, cfg->configDir, flags);

cleanup:
    virObjectUnlock(vm);
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
    virObjectUnlock(vm);
    virObjectUnref(caps);
    return ret;
}

/* qemuDomainGetCPUStats() with start_cpu == -1 */
static int
qemuDomainGetTotalcpuStats(virDomainObjPtr vm,
                           virTypedParameterPtr params,
                           int nparams)
{
    unsigned long long cpu_time;
    int ret;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (nparams == 0) /* return supported number of params */
        return QEMU_NB_TOTAL_CPU_STAT_PARAM;
    /* entry 0 is cputime */
    ret = virCgroupGetCpuacctUsage(priv->cgroup, &cpu_time);
    if (ret < 0) {
        virReportSystemError(-ret, "%s", _("unable to get cpu account"));
        return -1;
    }

    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_CPU_STATS_CPUTIME,
                                VIR_TYPED_PARAM_ULLONG, cpu_time) < 0)
        return -1;

    if (nparams > 1) {
        unsigned long long user;
        unsigned long long sys;

        ret = virCgroupGetCpuacctStat(priv->cgroup, &user, &sys);
        if (ret < 0) {
            virReportSystemError(-ret, "%s", _("unable to get cpu account"));
            return -1;
        }

        if (virTypedParameterAssign(&params[1],
                                    VIR_DOMAIN_CPU_STATS_USERTIME,
                                    VIR_TYPED_PARAM_ULLONG, user) < 0)
            return -1;
        if (nparams > 2 &&
            virTypedParameterAssign(&params[2],
                                    VIR_DOMAIN_CPU_STATS_SYSTEMTIME,
                                    VIR_TYPED_PARAM_ULLONG, sys) < 0)
            return -1;

        if (nparams > QEMU_NB_TOTAL_CPU_STAT_PARAM)
            nparams = QEMU_NB_TOTAL_CPU_STAT_PARAM;
    }

    return nparams;
}

/* This function gets the sums of cpu time consumed by all vcpus.
 * For example, if there are 4 physical cpus, and 2 vcpus in a domain,
 * then for each vcpu, the cpuacct.usage_percpu looks like this:
 *   t0 t1 t2 t3
 * and we have 2 groups of such data:
 *   v\p   0   1   2   3
 *   0   t00 t01 t02 t03
 *   1   t10 t11 t12 t13
 * for each pcpu, the sum is cpu time consumed by all vcpus.
 *   s0 = t00 + t10
 *   s1 = t01 + t11
 *   s2 = t02 + t12
 *   s3 = t03 + t13
 */
static int
getSumVcpuPercpuStats(virDomainObjPtr vm,
                      unsigned long long *sum_cpu_time,
                      unsigned int num)
{
    int ret = -1;
    size_t i;
    char *buf = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr group_vcpu = NULL;

    for (i = 0; i < priv->nvcpupids; i++) {
        char *pos;
        unsigned long long tmp;
        size_t j;

        if (virCgroupNewVcpu(priv->cgroup, i, false, &group_vcpu) < 0)
            goto cleanup;

        if (virCgroupGetCpuacctPercpuUsage(group_vcpu, &buf) < 0)
            goto cleanup;

        pos = buf;
        for (j = 0; j < num; j++) {
            if (virStrToLong_ull(pos, &pos, 10, &tmp) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cpuacct parse error"));
                goto cleanup;
            }
            sum_cpu_time[j] += tmp;
        }

        virCgroupFree(&group_vcpu);
        VIR_FREE(buf);
    }

    ret = 0;
cleanup:
    virCgroupFree(&group_vcpu);
    VIR_FREE(buf);
    return ret;
}

static int
qemuDomainGetPercpuStats(virDomainObjPtr vm,
                         virTypedParameterPtr params,
                         unsigned int nparams,
                         int start_cpu,
                         unsigned int ncpus)
{
    int rv = -1;
    size_t i;
    int id, max_id;
    char *pos;
    char *buf = NULL;
    unsigned long long *sum_cpu_time = NULL;
    unsigned long long *sum_cpu_pos;
    unsigned int n = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virTypedParameterPtr ent;
    int param_idx;
    unsigned long long cpu_time;

    /* return the number of supported params */
    if (nparams == 0 && ncpus != 0)
        return QEMU_NB_PER_CPU_STAT_PARAM;

    /* To parse account file, we need to know how many cpus are present.  */
    max_id = nodeGetCPUCount();
    if (max_id < 0)
        return rv;

    if (ncpus == 0) { /* returns max cpu ID */
        rv = max_id;
        goto cleanup;
    }

    if (start_cpu > max_id) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("start_cpu %d larger than maximum of %d"),
                       start_cpu, max_id);
        goto cleanup;
    }

    /* we get percpu cputime accounting info. */
    if (virCgroupGetCpuacctPercpuUsage(priv->cgroup, &buf))
        goto cleanup;
    pos = buf;
    memset(params, 0, nparams * ncpus);

    /* return percpu cputime in index 0 */
    param_idx = 0;

    /* number of cpus to compute */
    if (start_cpu >= max_id - ncpus)
        id = max_id - 1;
    else
        id = start_cpu + ncpus - 1;

    for (i = 0; i <= id; i++) {
        if (virStrToLong_ull(pos, &pos, 10, &cpu_time) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cpuacct parse error"));
            goto cleanup;
        } else {
            n++;
        }
        if (i < start_cpu)
            continue;
        ent = &params[(i - start_cpu) * nparams + param_idx];
        if (virTypedParameterAssign(ent, VIR_DOMAIN_CPU_STATS_CPUTIME,
                                    VIR_TYPED_PARAM_ULLONG, cpu_time) < 0)
            goto cleanup;
    }

    /* return percpu vcputime in index 1 */
    if (++param_idx >= nparams) {
        rv = nparams;
        goto cleanup;
    }

    if (VIR_ALLOC_N(sum_cpu_time, n) < 0)
        goto cleanup;
    if (getSumVcpuPercpuStats(vm, sum_cpu_time, n) < 0)
        goto cleanup;

    sum_cpu_pos = sum_cpu_time;
    for (i = 0; i <= id; i++) {
        cpu_time = *(sum_cpu_pos++);
        if (i < start_cpu)
            continue;
        if (virTypedParameterAssign(&params[(i - start_cpu) * nparams +
                                            param_idx],
                                    VIR_DOMAIN_CPU_STATS_VCPUTIME,
                                    VIR_TYPED_PARAM_ULLONG,
                                    cpu_time) < 0)
            goto cleanup;
    }

    rv = param_idx + 1;
cleanup:
    VIR_FREE(sum_cpu_time);
    VIR_FREE(buf);
    return rv;
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
        ret = qemuDomainGetTotalcpuStats(vm, params, nparams);
    else
        ret = qemuDomainGetPercpuStats(vm, params, nparams,
                                       start_cpu, ncpus);
cleanup:
    if (vm)
        virObjectUnlock(vm);
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
        if (vm->def->pm.s3 == VIR_DOMAIN_PM_STATE_DISABLED &&
            (target == VIR_NODE_SUSPEND_TARGET_MEM ||
             target == VIR_NODE_SUSPEND_TARGET_HYBRID)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("S3 state is disabled for this domain"));
            goto cleanup;
        }

        if (vm->def->pm.s4 == VIR_DOMAIN_PM_STATE_DISABLED &&
            target == VIR_NODE_SUSPEND_TARGET_DISK) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("S4 state is disabled for this domain"));
            goto cleanup;
        }
    }

    if (priv->agentError) {
        virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                       _("QEMU guest agent is not "
                         "available due to an error"));
        goto cleanup;
    }

    if (!priv->agent) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("QEMU guest agent is not configured"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterAgent(vm);
    ret = qemuAgentSuspend(priv->agent, target);
    qemuDomainObjExitAgent(vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
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

    if (priv->agentError) {
        virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                       _("QEMU guest agent is not "
                         "available due to an error"));
        goto cleanup;
    }

    if (!priv->agent) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("QEMU guest agent is not configured"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

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
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return result;
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

    if (!priv->agent) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("QEMU guest agent is not configured"));
        goto cleanup;
    }

    if (priv->agentError) {
        virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                       _("QEMU guest agent is not "
                         "available due to an error"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterAgent(vm);
    ret = qemuAgentFSTrim(priv->agent, minimum);
    qemuDomainObjExitAgent(vm);

endjob:
    if (!qemuDomainObjEndJob(driver, vm))
        vm = NULL;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
qemuNodeGetInfo(virConnectPtr conn,
                virNodeInfoPtr nodeinfo)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return nodeGetInfo(nodeinfo);
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

    return nodeGetMemoryStats(cellNum, params, nparams, flags);
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
    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    return nodeGetFreeMemory();
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

    return nodeGetCPUMap(cpumap, online, flags);
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


static virDriver qemuDriver = {
    .no = VIR_DRV_QEMU,
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
    .domainOpenConsole = qemuDomainOpenConsole, /* 0.8.6 */
    .domainOpenGraphics = qemuDomainOpenGraphics, /* 0.9.7 */
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
};


static virStateDriver qemuStateDriver = {
    .name = "QEMU",
    .stateInitialize = qemuStateInitialize,
    .stateAutoStart = qemuStateAutoStart,
    .stateCleanup = qemuStateCleanup,
    .stateReload = qemuStateReload,
    .stateStop = qemuStateStop,
};

int qemuRegister(void) {
    virRegisterDriver(&qemuDriver);
    virRegisterStateDriver(&qemuStateDriver);
    return 0;
}
