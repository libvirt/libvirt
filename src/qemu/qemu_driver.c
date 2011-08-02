/*
 * qemu_driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
#include <byteswap.h>


#include "qemu_driver.h"
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

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "buf.h"
#include "util.h"
#include "nodeinfo.h"
#include "stats_linux.h"
#include "capabilities.h"
#include "memory.h"
#include "uuid.h"
#include "domain_conf.h"
#include "domain_audit.h"
#include "node_device_conf.h"
#include "pci.h"
#include "hostusb.h"
#include "processinfo.h"
#include "libvirt_internal.h"
#include "xml.h"
#include "cpu/cpu.h"
#include "macvtap.h"
#include "sysinfo.h"
#include "domain_nwfilter.h"
#include "hooks.h"
#include "storage_file.h"
#include "virfile.h"
#include "fdstream.h"
#include "configmake.h"
#include "threadpool.h"
#include "locking/lock_manager.h"
#include "virkeycode.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define QEMU_NB_MEM_PARAM  3

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

#define QEMU_NB_BLKIO_PARAM  1

static void processWatchdogEvent(void *data, void *opaque);

static int qemudShutdown(void);

static int qemuDomainObjStart(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              bool start_paused,
                              bool autodestroy,
                              bool bypass_cache);

static int qemudDomainGetMaxVcpus(virDomainPtr dom);

struct qemud_driver *qemu_driver = NULL;


struct qemuAutostartData {
    struct qemud_driver *driver;
    virConnectPtr conn;
};

static void
qemuAutostartDomain(void *payload, const void *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr vm = payload;
    struct qemuAutostartData *data = opaque;
    virErrorPtr err;

    virDomainObjLock(vm);
    virResetLastError();
    if (qemuDomainObjBeginJobWithDriver(data->driver, vm,
                                        QEMU_JOB_MODIFY) < 0) {
        err = virGetLastError();
        VIR_ERROR(_("Failed to start job on VM '%s': %s"),
                  vm->def->name,
                  err ? err->message : _("unknown error"));
    } else {
        if (vm->autostart &&
            !virDomainObjIsActive(vm) &&
            qemuDomainObjStart(data->conn, data->driver, vm,
                               false, false,
                               data->driver->autoStartBypassCache) < 0) {
            err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : _("unknown error"));
        }

        if (qemuDomainObjEndJob(data->driver, vm) == 0)
            vm = NULL;
    }

    if (vm)
        virDomainObjUnlock(vm);
}


static void
qemuAutostartDomains(struct qemud_driver *driver)
{
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

static int
qemuSecurityInit(struct qemud_driver *driver)
{
    virSecurityManagerPtr mgr = virSecurityManagerNew(driver->securityDriverName,
                                                      driver->allowDiskFormatProbing);
    if (!mgr)
        goto error;

    if (driver->privileged) {
        virSecurityManagerPtr dac = virSecurityManagerNewDAC(driver->user,
                                                             driver->group,
                                                             driver->allowDiskFormatProbing,
                                                             driver->dynamicOwnership);
        if (!dac)
            goto error;

        if (!(driver->securityManager = virSecurityManagerNewStack(mgr,
                                                                   dac))) {

            virSecurityManagerFree(dac);
            goto error;
        }
    } else {
        driver->securityManager = mgr;
    }

    return 0;

error:
    VIR_ERROR(_("Failed to initialize security drivers"));
    virSecurityManagerFree(mgr);
    return -1;
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
    const char *doi, *model;

    doi = virSecurityManagerGetDOI(driver->securityManager);
    model = virSecurityManagerGetModel(driver->securityManager);
    if (STRNEQ(model, "none")) {
        if (!(caps->host.secModel.model = strdup(model)))
            goto no_memory;
        if (!(caps->host.secModel.doi = strdup(doi)))
            goto no_memory;
    }

    VIR_DEBUG("Initialized caps for security driver \"%s\" with "
              "DOI \"%s\"", model, doi);

    return caps;

no_memory:
    virReportOOMError();
err_exit:
    virCapabilitiesFree(caps);
    return NULL;
}

static void qemuDomainSnapshotLoad(void *payload,
                                   const void *name ATTRIBUTE_UNUSED,
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
            VIR_ERROR(_("Failed to allocate memory for path"));
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
        VIR_ERROR(_("cannot initialize mutex"));
        VIR_FREE(qemu_driver);
        return -1;
    }
    qemuDriverLock(qemu_driver);
    qemu_driver->privileged = privileged;

    /* Don't have a dom0 so start from 1 */
    qemu_driver->nextvmid = 1;

    if (virDomainObjListInit(&qemu_driver->domains) < 0)
        goto out_of_memory;

    /* Init domain events */
    qemu_driver->domainEventState = virDomainEventStateNew(qemuDomainEventFlush,
                                                           qemu_driver,
                                                           NULL,
                                                           true);
    if (!qemu_driver->domainEventState)
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

    if (virFileMakePath(qemu_driver->stateDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create state dir '%s': %s"),
                  qemu_driver->stateDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->libDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create lib dir '%s': %s"),
                  qemu_driver->libDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->cacheDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create cache dir '%s': %s"),
                  qemu_driver->cacheDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->saveDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create save dir '%s': %s"),
                  qemu_driver->saveDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->snapshotDir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create save dir '%s': %s"),
                  qemu_driver->snapshotDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if (virFileMakePath(qemu_driver->autoDumpPath) < 0) {
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
        VIR_INFO("Unable to create cgroup for driver: %s",
                 virStrerror(-rc, buf, sizeof(buf)));
    }

    if (qemudLoadDriverConfig(qemu_driver, driverConf) < 0) {
        goto error;
    }
    VIR_FREE(driverConf);

    /* We should always at least have the 'nop' manager, so
     * NULLs here are a fatal error
     */
    if (!qemu_driver->lockManager) {
        VIR_ERROR(_("Missing lock manager implementation"));
        goto error;
    }

    if (qemuSecurityInit(qemu_driver) < 0)
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

        if (virFileMakePath(mempath) < 0) {
            virReportSystemError(errno,
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

    if (qemuProcessAutoDestroyInit(qemu_driver) < 0)
        goto error;

    /* Get all the running persistent or transient configs first */
    if (virDomainLoadAllConfigs(qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->stateDir,
                                NULL,
                                1, QEMU_EXPECTED_VIRT_TYPES,
                                NULL, NULL) < 0)
        goto error;

    conn = virConnectOpen(qemu_driver->privileged ?
                          "qemu:///system" :
                          "qemu:///session");

    qemuProcessReconnectAll(conn, qemu_driver);

    /* Then inactive persistent configs */
    if (virDomainLoadAllConfigs(qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->configDir,
                                qemu_driver->autostartDir,
                                0, QEMU_EXPECTED_VIRT_TYPES,
                                NULL, NULL) < 0)
        goto error;


    virHashForEach(qemu_driver->domains.objs, qemuDomainSnapshotLoad,
                   qemu_driver->snapshotDir);

    qemu_driver->workerPool = virThreadPoolNew(0, 1, processWatchdogEvent, qemu_driver);
    if (!qemu_driver->workerPool)
        goto error;

    qemuDriverUnlock(qemu_driver);

    qemuAutostartDomains(qemu_driver);

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
                            0, QEMU_EXPECTED_VIRT_TYPES,
                            qemudNotifyLoadDomain, qemu_driver);
    qemuDriverUnlock(qemu_driver);

    qemuAutostartDomains(qemu_driver);

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

    qemuProcessAutoDestroyShutdown(qemu_driver);

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
    VIR_FREE(qemu_driver->saveImageFormat);
    VIR_FREE(qemu_driver->dumpImageFormat);

    virSecurityManagerFree(qemu_driver->securityManager);

    ebtablesContextFree(qemu_driver->ebtables);

    if (qemu_driver->cgroupDeviceACL) {
        for (i = 0 ; qemu_driver->cgroupDeviceACL[i] != NULL ; i++)
            VIR_FREE(qemu_driver->cgroupDeviceACL[i]);
        VIR_FREE(qemu_driver->cgroupDeviceACL);
    }

    /* Free domain callback list */
    virDomainEventStateFree(qemu_driver->domainEventState);

    if (qemu_driver->brctl)
        brShutdown(qemu_driver->brctl);

    virCgroupFree(&qemu_driver->cgroup);

    virLockManagerPluginUnref(qemu_driver->lockManager);

    qemuDriverUnlock(qemu_driver);
    virMutexDestroy(&qemu_driver->lock);
    virThreadPoolFree(qemu_driver->workerPool);
    VIR_FREE(qemu_driver);

    return 0;
}


static int qemuDomainSnapshotSetCurrentActive(virDomainObjPtr vm,
                                              char *snapshotDir);
static int qemuDomainSnapshotSetCurrentInactive(virDomainObjPtr vm,
                                                char *snapshotDir);


static virDrvOpenStatus qemudOpen(virConnectPtr conn,
                                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                  unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

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
    virDomainEventCallbackListRemoveConn(conn,
                                         driver->domainEventState->callbacks);
    qemuProcessAutoDestroyRun(driver, conn);
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
    case VIR_DRV_FEATURE_MIGRATION_V3:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
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


static char *
qemuGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    struct qemud_driver *driver = conn->privateData;

    virCheckFlags(0, NULL);

    if (!driver->hostsysinfo) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("Host SMBIOS information is not available"));
        return NULL;
    }

    return virSysinfoFormat(driver->hostsysinfo, "");
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
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
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
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

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY, NULL);

    qemuDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (qemudCanonicalizeMachine(driver, def) < 0)
        goto cleanup;

    if (qemuDomainAssignPCIAddresses(def) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, false)))
        goto cleanup;

    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup; /* XXXX free the 'vm' we created ? */

    if (qemuProcessStart(conn, driver, vm, NULL,
                         (flags & VIR_DOMAIN_START_PAUSED) != 0,
                         (flags & VIR_DOMAIN_START_AUTODESTROY) != 0,
                         -1, NULL, VIR_VM_OP_CREATE) < 0) {
        virDomainAuditStart(vm, "booted", false);
        if (qemuDomainObjEndJob(driver, vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    virDomainAuditStart(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

    if (vm &&
        qemuDomainObjEndJob(driver, vm) == 0)
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
    virDomainPausedReason reason;
    int eventDetail;

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

    if (qemuProcessAutoDestroyActive(driver, vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is marked for auto destroy"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT) {
        reason = VIR_DOMAIN_PAUSED_MIGRATION;
        eventDetail = VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED;
    } else {
        reason = VIR_DOMAIN_PAUSED_USER;
        eventDetail = VIR_DOMAIN_EVENT_SUSPENDED_PAUSED;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_SUSPEND) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }
    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        if (qemuProcessStopCPUs(driver, vm, reason, QEMU_ASYNC_JOB_NONE) < 0) {
            goto endjob;
        }
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         eventDetail);
    }
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto endjob;
    ret = 0;

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
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

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        if (qemuProcessStartCPUs(driver, vm, dom->conn,
                                 VIR_DOMAIN_RUNNING_UNPAUSED,
                                 QEMU_ASYNC_JOB_NONE) < 0) {
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
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


static int qemuDomainShutdown(virDomainPtr dom) {
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

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSystemPowerdown(priv->mon);
    qemuDomainObjExitMonitor(driver, vm);

    priv->fakeReboot = false;

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int qemuDomainReboot(virDomainPtr dom, unsigned int flags) {
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
#if HAVE_YAJL
    qemuDomainObjPrivatePtr priv;
#endif

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

#if HAVE_YAJL
    priv = vm->privateData;

    if (qemuCapsGet(priv->qemuCaps, QEMU_CAPS_MONITOR_JSON)) {
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
            goto cleanup;

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto endjob;
        }

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorSystemPowerdown(priv->mon);
        qemuDomainObjExitMonitor(driver, vm);

        priv->fakeReboot = true;

    endjob:
        if (qemuDomainObjEndJob(driver, vm) == 0)
            vm = NULL;
    } else {
#endif
        qemuReportError(VIR_ERR_NO_SUPPORT, "%s",
                        _("Reboot is not supported without the JSON monitor"));
#if HAVE_YAJL
    }
#endif

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int
qemuDomainDestroyFlags(virDomainPtr dom,
                       unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm  = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    priv = vm->privateData;
    priv->fakeReboot = false;

    /* Although qemuProcessStop does this already, there may
     * be an outstanding job active. We want to make sure we
     * can kill the process even if a job is active. Killing
     * it now means the job will be released
     */
    qemuProcessKill(vm);

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_DESTROY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    qemuProcessStop(driver, vm, 0, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    virDomainAuditStop(vm, "destroyed");

    if (!vm->persistent) {
        if (qemuDomainObjEndJob(driver, vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
    }
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(driver, vm) == 0)
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
qemuDomainDestroy(virDomainPtr dom)
{
    return qemuDomainDestroyFlags(dom, 0);
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

static int qemudDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                                     unsigned int flags) {
    struct qemud_driver *driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1, r;
    bool isActive;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

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

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }
    if (flags == VIR_DOMAIN_MEM_MAXIMUM) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_MEM_MAXIMUM;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG | VIR_DOMAIN_MEM_MAXIMUM;
    }

    if (!isActive && (flags & VIR_DOMAIN_AFFECT_LIVE)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot change persistent config of a transient domain"));
            goto endjob;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        /* resize the maximum memory */

        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
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
            ret = virDomainSaveConfig(driver->configDir, persistentDef);
            goto endjob;
        }

    } else {
        /* resize the current memory */

        if (newmem > vm->def->mem.max_balloon) {
            qemuReportError(VIR_ERR_INVALID_ARG, "%s",
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
                qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                _("cannot set memory of an active domain"));
                goto endjob;
            }
        }

        if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
            sa_assert(persistentDef);
            persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(driver->configDir, persistentDef);
            goto endjob;
        }
    }

    ret = 0;
endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int qemudDomainSetMemory(virDomainPtr dom, unsigned long newmem)
{
    return qemudDomainSetMemoryFlags(dom, newmem, VIR_DOMAIN_AFFECT_LIVE);
}

static int qemudDomainSetMaxMemory(virDomainPtr dom, unsigned long memory)
{
    return qemudDomainSetMemoryFlags(dom, memory, VIR_DOMAIN_MEM_MAXIMUM);
}

static int qemuDomainInjectNMI(virDomainPtr domain, unsigned int flags)
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

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorInjectNMI(priv->mon);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (qemuDomainObjEndJob(driver, vm) == 0) {
        vm = NULL;
        goto cleanup;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainSendKey(virDomainPtr domain,
                             unsigned int codeset,
                             unsigned int holdtime,
                             unsigned int *keycodes,
                             int nkeycodes,
                             unsigned int flags)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    /* translate the keycode to XT_KBD for qemu driver */
    if (codeset != VIR_KEYCODE_SET_XT_KBD) {
        int i;
        int keycode;

        for (i = 0; i < nkeycodes; i++) {
            keycode = virKeycodeValueTranslate(codeset, VIR_KEYCODE_SET_XT_KBD,
                                               keycodes[i]);
            if (keycode < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
             _("cannot translate keycode %u of %s codeset to xt_kbd keycode"),
                                keycodes[i],
                                virKeycodeSetTypeToString(codeset));
                return -1;
            }
            keycodes[i] = keycode;
        }
    }

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorSendKey(priv->mon, holdtime, keycodes, nkeycodes);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (qemuDomainObjEndJob(driver, vm) == 0) {
        vm = NULL;
        goto cleanup;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemudDomainGetInfo(virDomainPtr dom,
                              virDomainInfoPtr info)
{
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

    info->state = virDomainObjGetState(vm, NULL);

    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (qemudGetProcessInfo(&(info->cpuTime), NULL, vm->pid, 0) < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
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
        } else if (!priv->job.active) {
            if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
                goto cleanup;
            if (!virDomainObjIsActive(vm))
                err = 0;
            else {
                qemuDomainObjEnterMonitor(driver, vm);
                err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
                qemuDomainObjExitMonitor(driver, vm);
            }
            if (qemuDomainObjEndJob(driver, vm) == 0) {
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

static int
qemuDomainGetState(virDomainPtr dom,
                   int *state,
                   int *reason,
                   unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

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

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
qemuDomainGetControlInfo(virDomainPtr dom,
                          virDomainControlInfoPtr info,
                          unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

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

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
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
            if (virTimeMs(&info->stateTime) < 0)
                goto cleanup;
            info->stateTime -= priv->job.start;
        } else {
            info->state = VIR_DOMAIN_CONTROL_OCCUPIED;
            if (virTimeMs(&info->stateTime) < 0)
                goto cleanup;
            info->stateTime -= priv->monStart;
        }
    } else {
        info->state = VIR_DOMAIN_CONTROL_OK;
    }

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
    uint32_t version;
    uint32_t xml_len;
    uint32_t was_running;
    uint32_t compressed;
    uint32_t unused[15];
};

static inline void
bswap_header(struct qemud_save_header *hdr) {
    hdr->version = bswap_32(hdr->version);
    hdr->xml_len = bswap_32(hdr->xml_len);
    hdr->was_running = bswap_32(hdr->was_running);
    hdr->compressed = bswap_32(hdr->compressed);
}


/* return -errno on failure, or 0 on success */
static int
qemuDomainSaveHeader(int fd, const char *path, char *xml,
                     struct qemud_save_header *header)
{
    int ret = 0;

    if (safewrite(fd, header, sizeof(*header)) != sizeof(*header)) {
        ret = -errno;
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("failed to write header to domain save file '%s'"),
                        path);
        goto endjob;
    }

    if (safewrite(fd, xml, header->xml_len) != header->xml_len) {
        ret = -errno;
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                         _("failed to write xml to '%s'"), path);
        goto endjob;
    }
endjob:
    return ret;
}

/* Given a enum qemud_save_formats compression level, return the name
 * of the program to run, or NULL if no program is needed.  */
static const char *
qemuCompressProgramName(int compress)
{
    return (compress == QEMUD_SAVE_FORMAT_RAW ? NULL :
            qemudSaveCompressionTypeToString(compress));
}

/* This internal function expects the driver lock to already be held on
 * entry and the vm must be active + locked. Vm will be unlocked and
 * potentially free'd after this returns (eg transient VMs are freed
 * shutdown). So 'vm' must not be referenced by the caller after
 * this returns (whether returning success or failure).
 */
static int
qemuDomainSaveInternal(struct qemud_driver *driver, virDomainPtr dom,
                       virDomainObjPtr vm, const char *path,
                       int compressed, bool bypass_cache, const char *xmlin)
{
    char *xml = NULL;
    struct qemud_save_header header;
    bool bypassSecurityDriver = false;
    int ret = -1;
    int rc;
    virDomainEventPtr event = NULL;
    qemuDomainObjPrivatePtr priv;
    struct stat sb;
    bool is_reg = false;
    size_t len;
    unsigned long long offset;
    unsigned long long pad;
    int fd = -1;
    uid_t uid = getuid();
    gid_t gid = getgid();
    int directFlag = 0;
    virFileDirectFdPtr directFd = NULL;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic));
    header.version = QEMUD_SAVE_VERSION;

    header.compressed = compressed;

    priv = vm->privateData;

    if (qemuDomainObjBeginAsyncJobWithDriver(driver, vm,
                                             QEMU_ASYNC_JOB_SAVE) < 0)
        goto cleanup;

    memset(&priv->job.info, 0, sizeof(priv->job.info));
    priv->job.info.type = VIR_DOMAIN_JOB_UNBOUNDED;

    /* Pause */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        header.was_running = 1;
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_SAVE,
                                QEMU_ASYNC_JOB_SAVE) < 0)
            goto endjob;

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto endjob;
        }
    }

    /* Get XML for the domain.  Restore needs only the inactive xml,
     * including secure.  We should get the same result whether xmlin
     * is NULL or whether it was the live xml of the domain moments
     * before.  */
    if (xmlin) {
        virDomainDefPtr def = NULL;

        if (!(def = virDomainDefParseString(driver->caps, xmlin,
                                            QEMU_EXPECTED_VIRT_TYPES,
                                            VIR_DOMAIN_XML_INACTIVE))) {
            goto endjob;
        }
        if (!virDomainDefCheckABIStability(vm->def, def)) {
            virDomainDefFree(def);
            goto endjob;
        }
        xml = virDomainDefFormat(def, (VIR_DOMAIN_XML_INACTIVE |
                                       VIR_DOMAIN_XML_SECURE));
    } else {
        xml = virDomainDefFormat(vm->def, (VIR_DOMAIN_XML_INACTIVE |
                                           VIR_DOMAIN_XML_SECURE));
    }
    if (!xml) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to get domain xml"));
        goto endjob;
    }
    len = strlen(xml) + 1;
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
    if (VIR_EXPAND_N(xml, len, pad) < 0) {
        virReportOOMError();
        goto endjob;
    }
    offset += pad;
    header.xml_len = len;

    /* Obtain the file handle.  */
    /* path might be a pre-existing block dev, in which case
     * we need to skip the create step, and also avoid unlink
     * in the failure case */
    if (stat(path, &sb) < 0) {
        /* Avoid throwing an error here, since it is possible
         * that with NFS we can't actually stat() the file.
         * The subsequent codepaths will still raise an error
         * if a truely fatal problem is hit */
        is_reg = true;
    } else {
        is_reg = !!S_ISREG(sb.st_mode);
        /* If the path is regular file which exists
         * already and dynamic_ownership is off, we don't
         * want to change it's ownership, just open it as-is */
        if (is_reg && !driver->dynamicOwnership) {
            uid=sb.st_uid;
            gid=sb.st_gid;
        }
    }

    /* First try creating the file as root */
    if (bypass_cache) {
        directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("bypass cache unsupported by this system"));
            goto endjob;
        }
    }
    if (!is_reg) {
        fd = open(path, O_WRONLY | O_TRUNC | directFlag);
        if (fd < 0) {
            virReportSystemError(errno, _("unable to open %s"), path);
            goto endjob;
        }
    } else {
        int oflags = O_CREAT | O_TRUNC | O_WRONLY | directFlag;
        if ((fd = virFileOpenAs(path, oflags, S_IRUSR | S_IWUSR,
                                uid, gid, 0)) < 0) {
            /* If we failed as root, and the error was permission-denied
               (EACCES or EPERM), assume it's on a network-connected share
               where root access is restricted (eg, root-squashed NFS). If the
               qemu user (driver->user) is non-root, just set a flag to
               bypass security driver shenanigans, and retry the operation
               after doing setuid to qemu user */
            rc = fd;
            if (((rc != -EACCES) && (rc != -EPERM)) ||
                driver->user == getuid()) {
                virReportSystemError(-rc,
                                    _("Failed to create domain save file '%s'"),
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
                   /* local file - log the error returned by virFileOpenAs */
                   virReportSystemError(-rc,
                                    _("Failed to create domain save file '%s'"),
                                        path);
                   goto endjob;
                   break;

            }

            /* Retry creating the file as driver->user */

            if ((fd = virFileOpenAs(path, oflags,
                                    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP,
                                    driver->user, driver->group,
                                    VIR_FILE_OPEN_AS_UID)) < 0) {
                virReportSystemError(-fd,
                                   _("Error from child process creating '%s'"),
                                     path);
                goto endjob;
            }

            /* Since we had to setuid to create the file, and the fstype
               is NFS, we assume it's a root-squashing NFS share, and that
               the security driver stuff would have failed anyway */

            bypassSecurityDriver = true;
        }
    }

    if (bypass_cache && (directFd = virFileDirectFdNew(&fd, path)) == NULL)
        goto endjob;

    /* Write header to file, followed by XML */
    if (qemuDomainSaveHeader(fd, path, xml, &header) < 0) {
        VIR_FORCE_CLOSE(fd);
        goto endjob;
    }

    /* Perform the migration */
    if (qemuMigrationToFile(driver, vm, fd, offset, path,
                            qemuCompressProgramName(compressed),
                            is_reg, bypassSecurityDriver,
                            QEMU_ASYNC_JOB_SAVE) < 0)
        goto endjob;
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("unable to close %s"), path);
        goto endjob;
    }
    if (virFileDirectFdClose(directFd) < 0)
        goto endjob;

    ret = 0;

    /* Shut it down */
    qemuProcessStop(driver, vm, 0, VIR_DOMAIN_SHUTOFF_SAVED);
    virDomainAuditStop(vm, "saved");
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SAVED);
    if (!vm->persistent) {
        if (qemuDomainObjEndAsyncJob(driver, vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
    }

endjob:
    if (vm) {
        if (ret != 0) {
            if (header.was_running && virDomainObjIsActive(vm)) {
                rc = qemuProcessStartCPUs(driver, vm, dom->conn,
                                          VIR_DOMAIN_RUNNING_SAVE_CANCELED,
                                          QEMU_ASYNC_JOB_SAVE);
                if (rc < 0)
                    VIR_WARN("Unable to resume guest CPUs after save failure");
            }
        }
        if (qemuDomainObjEndAsyncJob(driver, vm) == 0)
            vm = NULL;
    }

cleanup:
    VIR_FORCE_CLOSE(fd);
    virFileDirectFdFree(directFd);
    VIR_FREE(xml);
    if (ret != 0 && is_reg)
        unlink(path);
    if (event)
        qemuDomainEventQueue(driver, event);
    if (vm)
        virDomainObjUnlock(vm);
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

static int
qemuDomainSaveFlags(virDomainPtr dom, const char *path, const char *dxml,
                    unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int compressed;
    int ret = -1;
    virDomainObjPtr vm = NULL;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE, -1);

    qemuDriverLock(driver);

    if (driver->saveImageFormat == NULL)
        compressed = QEMUD_SAVE_FORMAT_RAW;
    else {
        compressed = qemudSaveCompressionTypeFromString(driver->saveImageFormat);
        if (compressed < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Invalid save image format specified "
                                    "in configuration file"));
            goto cleanup;
        }
        if (!qemudCompressProgramAvailable(compressed)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("Compression program for image format "
                                    "in configuration file isn't available"));
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

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    ret = qemuDomainSaveInternal(driver, dom, vm, path, compressed,
                                 (flags & VIR_DOMAIN_SAVE_BYPASS_CACHE) != 0,
                                 dxml);
    vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);

    return ret;
}

static int
qemuDomainSave(virDomainPtr dom, const char *path)
{
    return qemuDomainSaveFlags(dom, path, NULL, 0);
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

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE, -1);

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

    name = qemuDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    VIR_INFO("Saving state to %s", name);

    compressed = QEMUD_SAVE_FORMAT_RAW;
    ret = qemuDomainSaveInternal(driver, dom, vm, name, compressed,
                                 (flags & VIR_DOMAIN_SAVE_BYPASS_CACHE) != 0,
                                 NULL);
    vm = NULL;

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

static int
doCoreDump(struct qemud_driver *driver,
           virDomainObjPtr vm,
           const char *path,
           enum qemud_save_formats compress,
           bool bypass_cache)
{
    int fd = -1;
    int ret = -1;
    virFileDirectFdPtr directFd = NULL;
    int directFlag = 0;

    /* Create an empty file with appropriate ownership.  */
    if (bypass_cache) {
        directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("bypass cache unsupported by this system"));
            goto cleanup;
        }
    }
    if ((fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | directFlag,
                   S_IRUSR | S_IWUSR)) < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("failed to create '%s'"), path);
        goto cleanup;
    }

    if (bypass_cache && (directFd = virFileDirectFdNew(&fd, path)) == NULL)
        goto cleanup;

    if (qemuMigrationToFile(driver, vm, fd, 0, path,
                            qemuCompressProgramName(compress), true, false,
                            QEMU_ASYNC_JOB_DUMP) < 0)
        goto cleanup;

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("unable to save file %s"),
                             path);
        goto cleanup;
    }
    if (virFileDirectFdClose(directFd) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    virFileDirectFdFree(directFd);
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
        /* Use "raw" as the format if the specified format is not valid,
         * or the compress program is not available.
         */
        if (compress < 0) {
            VIR_WARN("%s", _("Invalid dump image format specified in "
                             "configuration file, using raw"));
            return QEMUD_SAVE_FORMAT_RAW;
        }
        if (!qemudCompressProgramAvailable(compress)) {
            VIR_WARN("%s", _("Compression program for dump image format "
                             "in configuration file isn't available, "
                             "using raw"));
            return QEMUD_SAVE_FORMAT_RAW;
        }
    }
    return compress;
}

static int qemudDomainCoreDump(virDomainPtr dom,
                               const char *path,
                               unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int resume = 0, paused = 0;
    int ret = -1;
    virDomainEventPtr event = NULL;

    virCheckFlags(VIR_DUMP_LIVE | VIR_DUMP_CRASH | VIR_DUMP_BYPASS_CACHE, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginAsyncJobWithDriver(driver, vm,
                                             QEMU_ASYNC_JOB_DUMP) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
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
        paused = 1;

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto endjob;
        }
    }

    ret = doCoreDump(driver, vm, path, getCompressionType(driver),
                     (flags & VIR_DUMP_BYPASS_CACHE) != 0);
    if (ret < 0)
        goto endjob;

    paused = 1;

endjob:
    if ((ret == 0) && (flags & VIR_DUMP_CRASH)) {
        qemuProcessStop(driver, vm, 0, VIR_DOMAIN_SHUTOFF_CRASHED);
        virDomainAuditStop(vm, "crashed");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    }

    /* Since the monitor is always attached to a pty for libvirt, it
       will support synchronous operations so we always get here after
       the migration is complete.  */
    else if (resume && paused && virDomainObjIsActive(vm)) {
        if (qemuProcessStartCPUs(driver, vm, dom->conn,
                                 VIR_DOMAIN_RUNNING_UNPAUSED,
                                 QEMU_ASYNC_JOB_DUMP) < 0) {
            if (virGetLastError() == NULL)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("resuming after dump failed"));
        }
    }

    if (qemuDomainObjEndAsyncJob(driver, vm) == 0)
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

static char *
qemuDomainScreenshot(virDomainPtr dom,
                     virStreamPtr st,
                     unsigned int screen,
                     unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    char *tmp = NULL;
    int tmp_fd = -1;
    char *ret = NULL;
    bool unlink_tmp = false;

    virCheckFlags(0, NULL);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    priv = vm->privateData;

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    /* Well, even if qemu allows multiple graphic cards, heads, whatever,
     * screenshot command does not */
    if (screen) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("currently is supported only taking "
                                "screenshots of screen ID 0"));
        goto endjob;
    }

    if (virAsprintf(&tmp, "%s/qemu.screendump.XXXXXX", driver->cacheDir) < 0) {
        virReportOOMError();
        goto endjob;
    }

    if ((tmp_fd = mkstemp(tmp)) == -1) {
        virReportSystemError(errno, _("mkstemp(\"%s\") failed"), tmp);
        goto endjob;
    }
    unlink_tmp = true;

    virSecurityManagerSetSavedStateLabel(qemu_driver->securityManager, vm, tmp);

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
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("unable to open stream"));
        goto endjob;
    }

    ret = strdup("image/x-portable-pixmap");

endjob:
    VIR_FORCE_CLOSE(tmp_fd);
    if (unlink_tmp)
        unlink(tmp);
    VIR_FREE(tmp);

    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static void processWatchdogEvent(void *data, void *opaque)
{
    int ret;
    struct qemuDomainWatchdogEvent *wdEvent = data;
    struct qemud_driver *driver = opaque;

    qemuDriverLock(driver);
    virDomainObjLock(wdEvent->vm);

    switch (wdEvent->action) {
    case VIR_DOMAIN_WATCHDOG_ACTION_DUMP:
        {
            char *dumpfile;

            if (virAsprintf(&dumpfile, "%s/%s-%u",
                            driver->autoDumpPath,
                            wdEvent->vm->def->name,
                            (unsigned int)time(NULL)) < 0) {
                virReportOOMError();
                goto unlock;
            }

            if (qemuDomainObjBeginAsyncJobWithDriver(driver, wdEvent->vm,
                                                     QEMU_ASYNC_JOB_DUMP) < 0) {
                VIR_FREE(dumpfile);
                goto unlock;
            }

            if (!virDomainObjIsActive(wdEvent->vm)) {
                qemuReportError(VIR_ERR_OPERATION_INVALID,
                                "%s", _("domain is not running"));
                VIR_FREE(dumpfile);
                goto endjob;
            }

            ret = doCoreDump(driver, wdEvent->vm, dumpfile,
                             getCompressionType(driver),
                             driver->autoDumpBypassCache);
            if (ret < 0)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("Dump failed"));

            ret = qemuProcessStartCPUs(driver, wdEvent->vm, NULL,
                                       VIR_DOMAIN_RUNNING_UNPAUSED,
                                       QEMU_ASYNC_JOB_DUMP);

            if (ret < 0)
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                "%s", _("Resuming after dump failed"));

            VIR_FREE(dumpfile);
        }
        break;
    default:
        goto unlock;
    }

endjob:
    /* Safe to ignore value since ref count was incremented in
     * qemuProcessHandleWatchdog().
     */
    ignore_value(qemuDomainObjEndAsyncJob(driver, wdEvent->vm));

unlock:
    if (virDomainObjUnref(wdEvent->vm) > 0)
        virDomainObjUnlock(wdEvent->vm);
    qemuDriverUnlock(driver);
    VIR_FREE(wdEvent);
}

static int qemudDomainHotplugVcpus(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   unsigned int nvcpus)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, rc = 1;
    int ret = -1;
    int oldvcpus = vm->def->vcpus;
    int vcpus = oldvcpus;

    qemuDomainObjEnterMonitor(driver, vm);

    /* We need different branches here, because we want to offline
     * in reverse order to onlining, so any partial fail leaves us in a
     * reasonably sensible state */
    if (nvcpus > vcpus) {
        for (i = vcpus ; i < nvcpus ; i++) {
            /* Online new CPU */
            rc = qemuMonitorSetCPU(priv->mon, i, 1);
            if (rc == 0)
                goto unsupported;
            if (rc < 0)
                goto cleanup;

            vcpus++;
        }
    } else {
        for (i = vcpus - 1 ; i >= nvcpus ; i--) {
            /* Offline old CPU */
            rc = qemuMonitorSetCPU(priv->mon, i, 0);
            if (rc == 0)
                goto unsupported;
            if (rc < 0)
                goto cleanup;

            vcpus--;
        }
    }

    ret = 0;

cleanup:
    qemuDomainObjExitMonitor(driver, vm);
    vm->def->vcpus = vcpus;
    virDomainAuditVcpu(vm, oldvcpus, nvcpus, "update", rc == 1);
    return ret;

unsupported:
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot change vcpu count of this domain"));
    goto cleanup;
}


static int
qemuDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                        unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef;
    const char * type;
    int max;
    int ret = -1;
    bool isActive;
    bool maximum;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

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

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    isActive = virDomainObjIsActive(vm);
    maximum = (flags & VIR_DOMAIN_VCPU_MAXIMUM) != 0;
    flags &= ~VIR_DOMAIN_VCPU_MAXIMUM;

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        else
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
    }

    /* MAXIMUM cannot be mixed with LIVE.  */
    if (maximum && (flags & VIR_DOMAIN_AFFECT_LIVE)) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("cannot adjust maximum on running domain"));
        goto endjob;
    }

    if (!isActive && (flags & VIR_DOMAIN_AFFECT_LIVE)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                         "%s", _("domain is not running"));
        goto endjob;
    }

    if (!vm->persistent && (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
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

    if (!maximum && vm->def->maxvcpus < max) {
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
    case VIR_DOMAIN_AFFECT_CONFIG:
        if (maximum) {
            persistentDef->maxvcpus = nvcpus;
            if (nvcpus < persistentDef->vcpus)
                persistentDef->vcpus = nvcpus;
        } else {
            persistentDef->vcpus = nvcpus;
        }
        ret = 0;
        break;

    case VIR_DOMAIN_AFFECT_LIVE:
        ret = qemudDomainHotplugVcpus(driver, vm, nvcpus);
        break;

    case VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG:
        ret = qemudDomainHotplugVcpus(driver, vm, nvcpus);
        if (ret == 0) {
            persistentDef->vcpus = nvcpus;
        }
        break;
    }

    /* Save the persistent config to disk */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        ret = virDomainSaveConfig(driver->configDir, persistentDef);

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
qemuDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return qemuDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}


static int
qemudDomainPinVcpuFlags(virDomainPtr dom,
                        unsigned int vcpu,
                        unsigned char *cpumap,
                        int maplen,
                        unsigned int flags) {

    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    int maxcpu, hostcpus;
    virNodeInfo nodeinfo;
    int ret = -1;
    bool isActive;
    qemuDomainObjPrivatePtr priv;
    bool canResetting = true;
    int pcpu;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

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

    isActive = virDomainObjIsActive(vm);
    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (!isActive && (flags & VIR_DOMAIN_AFFECT_LIVE)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("a domain is inactive; can change only "
                          "persistent config"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (vcpu > (priv->nvcpupids-1)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("vcpu number out of range %d > %d"),
                        vcpu, priv->nvcpupids);
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("cannot change persistent config of a transient domain"));
            goto cleanup;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto cleanup;
    }

    if (nodeGetInfo(dom->conn, &nodeinfo) < 0)
        goto cleanup;
    hostcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;
    /* pinning to all physical cpus means resetting,
     * so check if we can reset setting.
     */
    for (pcpu = 0; pcpu < hostcpus; pcpu++) {
        if ((cpumap[pcpu/8] & (1 << (pcpu % 8))) == 0) {
            canResetting = false;
            break;
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {

        if (priv->vcpupids != NULL) {
            if (virProcessInfoSetAffinity(priv->vcpupids[vcpu],
                                          cpumap, maplen, maxcpu) < 0)
                goto cleanup;
        } else {
            qemuReportError(VIR_ERR_NO_SUPPORT,
                            "%s", _("cpu affinity is not supported"));
            goto cleanup;
        }

        if (canResetting) {
            if (virDomainVcpuPinDel(vm->def, vcpu) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("failed to delete vcpupin xml of "
                                  "a running domain"));
                goto cleanup;
            }
        } else {
            if (virDomainVcpuPinAdd(vm->def, cpumap, maplen, vcpu) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("failed to update or add vcpupin xml of "
                                  "a running domain"));
                goto cleanup;
            }
        }

        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {

        if (canResetting) {
            if (virDomainVcpuPinDel(persistentDef, vcpu) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("failed to delete vcpupin xml of "
                                  "a persistent domain"));
                goto cleanup;
            }
        } else {
            if (virDomainVcpuPinAdd(persistentDef, cpumap, maplen, vcpu) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("failed to update or add vcpupin xml of "
                                  "a persistent domain"));
                goto cleanup;
            }
        }

        ret = virDomainSaveConfig(driver->configDir, persistentDef);
        goto cleanup;
    }

    ret = 0;

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
    return qemudDomainPinVcpuFlags(dom, vcpu, cpumap, maplen,
                                   VIR_DOMAIN_AFFECT_LIVE);
}

static int
qemudDomainGetVcpuPinInfo(virDomainPtr dom,
                          int ncpumaps,
                          unsigned char *cpumaps,
                          int maplen,
                          unsigned int flags) {

    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virNodeInfo nodeinfo;
    virDomainDefPtr targetDef = NULL;
    int ret = -1;
    bool isActive;
    int maxcpu, hostcpus, vcpu, pcpu;
    int n;
    virDomainVcpuPinDefPtr *vcpupin_list;
    char *cpumask = NULL;
    unsigned char *cpumap;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if ((flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG)) ==
        (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG)) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("cannot get live and persistent info concurrently"));
        goto cleanup;
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

    isActive = virDomainObjIsActive(vm);
    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!isActive) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto cleanup;
        }
        targetDef = vm->def;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("cannot get persistent config of a transient domain"));
            goto cleanup;
        }
        if (!(targetDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto cleanup;
    }

    /* Coverity didn't realize that targetDef must be set if we got here.  */
    sa_assert(targetDef);

    if (nodeGetInfo(dom->conn, &nodeinfo) < 0)
        goto cleanup;
    hostcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
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
            if (cpumask[pcpu] == 0)
                VIR_UNUSE_CPU(cpumap, pcpu);
        }
    }
    ret = ncpumaps;

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
    bool active;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

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

    active = virDomainObjIsActive(vm);

    if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) == 0) {
        if (active)
            flags |= VIR_DOMAIN_VCPU_LIVE;
        else
            flags |= VIR_DOMAIN_VCPU_CONFIG;
    }
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) && (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!active) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("domain not active"));
            goto cleanup;
        }
        def = vm->def;
    } else {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("domain is transient"));
            goto cleanup;
        }
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
    return qemudDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
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
        if (virSecurityManagerGetProcessLabel(driver->securityManager,
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
    memset(secmodel, 0, sizeof(*secmodel));

    /* NULL indicates no driver, which we treat as
     * success, but simply return no data in *secmodel */
    if (driver->caps->host.secModel.model == NULL)
        goto cleanup;

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

/* Return -1 on failure, -2 if edit was specified but xmlin does not
 * represent any changes, and opened fd on all other success.  */
static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
qemuDomainSaveImageOpen(struct qemud_driver *driver,
                        const char *path,
                        virDomainDefPtr *ret_def,
                        struct qemud_save_header *ret_header,
                        bool bypass_cache, virFileDirectFdPtr *directFd,
                        const char *xmlin, bool edit)
{
    int fd;
    struct qemud_save_header header;
    char *xml = NULL;
    virDomainDefPtr def = NULL;
    int oflags = edit ? O_RDWR : O_RDONLY;

    if (bypass_cache) {
        int directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("bypass cache unsupported by this system"));
            goto error;
        }
        oflags |= directFlag;
    }
    if ((fd = virFileOpenAs(path, oflags, 0,
                            getuid(), getgid(), 0)) < 0) {
        if ((fd != -EACCES && fd != -EPERM) ||
            driver->user == getuid()) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("cannot read domain image"));
            goto error;
        }

        /* Opening as root failed, but qemu runs as a different user
         * that might have better luck. */
        if ((fd = virFileOpenAs(path, oflags, 0,
                                driver->user, driver->group,
                                VIR_FILE_OPEN_AS_UID)) < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("cannot read domain image"));
            goto error;
        }
    }
    if (bypass_cache && (*directFd = virFileDirectFdNew(&fd, path)) == NULL)
        goto error;

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
        /* convert endianess and try again */
        bswap_header(&header);
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

    if (edit && STREQ(xml, xmlin)) {
        VIR_FREE(xml);
        if (VIR_CLOSE(fd) < 0) {
            virReportSystemError(errno, _("cannot close file: %s"), path);
            goto error;
        }
        return -2;
    }

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto error;
    if (xmlin) {
        virDomainDefPtr def2 = NULL;

        if (!(def2 = virDomainDefParseString(driver->caps, xmlin,
                                             QEMU_EXPECTED_VIRT_TYPES,
                                             VIR_DOMAIN_XML_INACTIVE)))
            goto error;
        if (!virDomainDefCheckABIStability(def, def2)) {
            virDomainDefFree(def2);
            goto error;
        }
        virDomainDefFree(def);
        def = def2;
    }

    VIR_FREE(xml);

    *ret_def = def;
    *ret_header = header;

    return fd;

error:
    virDomainDefFree(def);
    VIR_FREE(xml);
    VIR_FORCE_CLOSE(fd);

    return -1;
}

static int ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6)
qemuDomainSaveImageStartVM(virConnectPtr conn,
                           struct qemud_driver *driver,
                           virDomainObjPtr vm,
                           int *fd,
                           const struct qemud_save_header *header,
                           const char *path)
{
    int ret = -1;
    virDomainEventPtr event;
    int intermediatefd = -1;
    virCommandPtr cmd = NULL;

    if (header->version == 2) {
        const char *prog = qemudSaveCompressionTypeToString(header->compressed);
        if (prog == NULL) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("Invalid compressed save format %d"),
                            header->compressed);
            goto out;
        }

        if (header->compressed != QEMUD_SAVE_FORMAT_RAW) {
            cmd = virCommandNewArgList(prog, "-dc", NULL);
            intermediatefd = *fd;
            *fd = -1;

            virCommandSetInputFD(cmd, intermediatefd);
            virCommandSetOutputFD(cmd, fd);

            if (virCommandRunAsync(cmd, NULL) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Failed to start decompression binary %s"),
                                prog);
                *fd = intermediatefd;
                goto out;
            }
        }
    }

    /* Set the migration source and start it up. */
    ret = qemuProcessStart(conn, driver, vm, "stdio", true,
                           false, *fd, path, VIR_VM_OP_RESTORE);

    if (intermediatefd != -1) {
        if (ret < 0) {
            /* if there was an error setting up qemu, the intermediate
             * process will wait forever to write to stdout, so we
             * must manually kill it.
             */
            VIR_FORCE_CLOSE(intermediatefd);
            VIR_FORCE_CLOSE(*fd);
        }

        if (virCommandWait(cmd, NULL) < 0)
            ret = -1;
    }
    VIR_FORCE_CLOSE(intermediatefd);

    if (VIR_CLOSE(*fd) < 0) {
        virReportSystemError(errno, _("cannot close file: %s"), path);
        ret = -1;
    }

    if (ret < 0) {
        virDomainAuditStart(vm, "restored", false);
        goto out;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    virDomainAuditStart(vm, "restored", true);
    if (event)
        qemuDomainEventQueue(driver, event);


    /* If it was running before, resume it now. */
    if (header->was_running) {
        if (qemuProcessStartCPUs(driver, vm, conn,
                                 VIR_DOMAIN_RUNNING_RESTORED,
                                 QEMU_ASYNC_JOB_NONE) < 0) {
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
    virCommandFree(cmd);
    if (virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                 vm, path) < 0)
        VIR_WARN("failed to restore save state label on %s", path);

    return ret;
}

static int
qemuDomainRestoreFlags(virConnectPtr conn,
                       const char *path,
                       const char *dxml,
                       unsigned int flags)
{
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int fd = -1;
    int ret = -1;
    struct qemud_save_header header;
    virFileDirectFdPtr directFd = NULL;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE, -1);

    qemuDriverLock(driver);

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header,
                                 (flags & VIR_DOMAIN_SAVE_BYPASS_CACHE) != 0,
                                 &directFd, dxml, false);
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

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    ret = qemuDomainSaveImageStartVM(conn, driver, vm, &fd, &header, path);
    if (virFileDirectFdClose(directFd) < 0)
        VIR_WARN("Failed to close %s", path);

    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;
    else if (ret < 0 && !vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    virFileDirectFdFree(directFd);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
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
    struct qemud_driver *driver = conn->privateData;
    char *ret = NULL;
    virDomainDefPtr def = NULL;
    int fd = -1;
    struct qemud_save_header header;

    /* We only take subset of virDomainDefFormat flags.  */
    virCheckFlags(VIR_DOMAIN_XML_SECURE, NULL);

    qemuDriverLock(driver);

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, false, NULL,
                                 NULL, false);

    if (fd < 0)
        goto cleanup;

    ret = qemuDomainDefFormatXML(driver, def, flags);

cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemuDomainSaveImageDefineXML(virConnectPtr conn, const char *path,
                             const char *dxml, unsigned int flags)
{
    struct qemud_driver *driver = conn->privateData;
    int ret = -1;
    virDomainDefPtr def = NULL;
    int fd = -1;
    struct qemud_save_header header;
    char *xml = NULL;
    size_t len;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header, false, NULL,
                                 dxml, true);

    if (fd < 0) {
        /* Check for special case of no change needed.  */
        if (fd == -2)
            ret = 0;
        goto cleanup;
    }

    xml = qemuDomainDefFormatXML(driver, def, (VIR_DOMAIN_XML_INACTIVE |
                                               VIR_DOMAIN_XML_SECURE));
    if (!xml)
        goto cleanup;
    len = strlen(xml) + 1;

    if (len > header.xml_len) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("new xml too large to fit in file"));
        goto cleanup;
    }
    if (VIR_EXPAND_N(xml, len, header.xml_len - len) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (lseek(fd, sizeof(header), SEEK_SET) != sizeof(header)) {
        virReportSystemError(errno, _("cannot seek in '%s'"), path);
        goto cleanup;
    }
    if (safewrite(fd, xml, len) != len ||
        VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("failed to write xml to '%s'"), path);
        goto cleanup;
    }

    ret = 0;

cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(xml);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemuDomainObjRestore(virConnectPtr conn,
                     struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     const char *path,
                     bool bypass_cache)
{
    virDomainDefPtr def = NULL;
    int fd = -1;
    int ret = -1;
    struct qemud_save_header header;
    virFileDirectFdPtr directFd = NULL;

    fd = qemuDomainSaveImageOpen(driver, path, &def, &header,
                                 bypass_cache, &directFd, NULL, false);
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

    ret = qemuDomainSaveImageStartVM(conn, driver, vm, &fd, &header, path);
    if (virFileDirectFdClose(directFd) < 0)
        VIR_WARN("Failed to close %s", path);

cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    virFileDirectFdFree(directFd);
    return ret;
}


static char *qemuDomainGetXMLDesc(virDomainPtr dom,
                                  unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;
    unsigned long balloon;
    int err;

    /* Flags checked by virDomainDefFormat */

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
        if (!priv->job.active) {
            if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_QUERY) < 0)
                goto cleanup;

            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            err = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (qemuDomainObjEndJob(driver, vm) == 0) {
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

    ret = qemuDomainFormatXML(driver, vm, flags);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}


static char *qemuDomainXMLFromNative(virConnectPtr conn,
                                     const char *format,
                                     const char *config,
                                     unsigned int flags)
{
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (STRNEQ(format, QEMU_CONFIG_FORMAT_ARGV)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        goto cleanup;
    }

    qemuDriverLock(driver);
    def = qemuParseCommandLineString(driver->caps, config,
                                     NULL, NULL, NULL);
    qemuDriverUnlock(driver);
    if (!def)
        goto cleanup;

    if (!def->name &&
        !(def->name = strdup("unnamed"))) {
        virReportOOMError();
        goto cleanup;
    }

    xml = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE);

cleanup:
    virDomainDefFree(def);
    return xml;
}

static char *qemuDomainXMLToNative(virConnectPtr conn,
                                   const char *format,
                                   const char *xmlData,
                                   unsigned int flags)
{
    struct qemud_driver *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainChrSourceDef monConfig;
    virBitmapPtr qemuCaps = NULL;
    virCommandPtr cmd = NULL;
    char *ret = NULL;
    int i;

    virCheckFlags(0, NULL);

    qemuDriverLock(driver);

    if (STRNEQ(format, QEMU_CONFIG_FORMAT_ARGV)) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        goto cleanup;
    }

    def = virDomainDefParseString(driver->caps, xmlData,
                                  QEMU_EXPECTED_VIRT_TYPES, 0);
    if (!def)
        goto cleanup;

    /* Since we're just exporting args, we can't do bridge/network/direct
     * setups, since libvirt will normally create TAP/macvtap devices
     * directly. We convert those configs into generic 'ethernet'
     * config and assume the user has suitable 'ifup-qemu' scripts
     */
    for (i = 0 ; i < def->nnets ; i++) {
        virDomainNetDefPtr net = def->nets[i];
        int bootIndex = net->bootIndex;
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            int actualType = virDomainNetGetActualType(net);
            const char *brname;

            VIR_FREE(net->data.network.name);
            VIR_FREE(net->data.network.portgroup);
            if ((actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) &&
                (brname = virDomainNetGetActualBridgeName(net))) {

                char *brnamecopy = strdup(brname);
                if (!brnamecopy) {
                    virReportOOMError();
                    goto cleanup;
                }

                virDomainActualNetDefFree(net->data.network.actual);

                memset(net, 0, sizeof *net);

                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                net->data.ethernet.dev = brnamecopy;
                net->data.ethernet.script = NULL;
                net->data.ethernet.ipaddr = NULL;
            } else {
                /* actualType is either NETWORK or DIRECT. In either
                 * case, the best we can do is NULL everything out.
                 */
                virDomainActualNetDefFree(net->data.network.actual);
                memset(net, 0, sizeof *net);

                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                net->data.ethernet.dev = NULL;
                net->data.ethernet.script = NULL;
                net->data.ethernet.ipaddr = NULL;
            }
        } else if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            VIR_FREE(net->data.direct.linkdev);
            VIR_FREE(net->data.direct.virtPortProfile);

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
        net->bootIndex = bootIndex;
    }
    for (i = 0 ; i < def->ngraphics ; i++) {
        if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            def->graphics[i]->data.vnc.autoport)
            def->graphics[i]->data.vnc.port = QEMU_VNC_PORT_MIN;
    }

    if (qemuCapsExtractVersionInfo(def->emulator, def->os.arch,
                                   NULL,
                                   &qemuCaps) < 0)
        goto cleanup;

    if (qemuProcessPrepareMonitorChr(driver, &monConfig, def->name) < 0)
        goto cleanup;

    if (!(cmd = qemuBuildCommandLine(conn, driver, def,
                                     &monConfig, false, qemuCaps,
                                     NULL, -1, NULL, VIR_VM_OP_NO_OP)))
        goto cleanup;

    ret = virCommandToString(cmd);

cleanup:
    qemuDriverUnlock(driver);

    qemuCapsFree(qemuCaps);
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


static int
qemuDomainObjStart(virConnectPtr conn,
                   struct qemud_driver *driver,
                   virDomainObjPtr vm,
                   bool start_paused,
                   bool autodestroy,
                   bool bypass_cache)
{
    int ret = -1;
    char *managed_save;

    /*
     * If there is a managed saved state restore it instead of starting
     * from scratch. The old state is removed once the restoring succeeded.
     */
    managed_save = qemuDomainManagedSavePath(driver, vm);

    if (!managed_save)
        goto cleanup;

    if (virFileExists(managed_save)) {
        ret = qemuDomainObjRestore(conn, driver, vm, managed_save,
                                   bypass_cache);

        if ((ret == 0) && (unlink(managed_save) < 0))
            VIR_WARN("Failed to remove the managed state %s", managed_save);

        goto cleanup;
    }

    ret = qemuProcessStart(conn, driver, vm, NULL, start_paused,
                           autodestroy, -1, NULL, VIR_VM_OP_CREATE);
    virDomainAuditStart(vm, "booted", ret >= 0);
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
qemuDomainStartWithFlags(virDomainPtr dom, unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_BYPASS_CACHE, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is already running"));
        goto endjob;
    }

    if (qemuDomainObjStart(dom->conn, driver, vm,
                           (flags & VIR_DOMAIN_START_PAUSED) != 0,
                           (flags & VIR_DOMAIN_START_AUTODESTROY) != 0,
                           (flags & VIR_DOMAIN_START_BYPASS_CACHE) != 0) < 0)
        goto endjob;

    ret = 0;

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemuDomainStart(virDomainPtr dom)
{
    return qemuDomainStartWithFlags(dom, 0);
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

        if (def->os.machine && STRNEQ(def->os.machine, machine->name))
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

    if (qemuCapsProbeMachineTypes(def->emulator, &machines, &nmachines) < 0)
        return -1;

    for (i = 0; i < nmachines; i++) {
        if (!machines[i]->canonical)
            continue;

        if (def->os.machine && STRNEQ(def->os.machine, machines[i]->name))
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
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if ((dupVM = virDomainObjIsDuplicate(&driver->domains, def, 0)) < 0)
        goto cleanup;

    if (qemudCanonicalizeMachine(driver, def) < 0)
        goto cleanup;

    if (qemuDomainAssignPCIAddresses(def) < 0)
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
        VIR_INFO("Defining domain '%s'", vm->def->name);
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

    VIR_INFO("Creating domain '%s'", vm->def->name);
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

static int
qemuDomainUndefineFlags(virDomainPtr dom,
                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    char *name = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE, -1);

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
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    name = qemuDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    if (virFileExists(name)) {
        if (flags & VIR_DOMAIN_UNDEFINE_MANAGED_SAVE) {
            if (unlink(name) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Failed to remove domain managed "
                                  "save image"));
                goto cleanup;
            }
        } else {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("Refusing to undefine while domain managed "
                              "save image exists"));
            goto cleanup;
        }
    }

    if (virDomainDeleteConfig(driver->configDir, driver->autostartDir, vm) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    VIR_INFO("Undefining domain '%s'", vm->def->name);
    virDomainRemoveInactive(&driver->domains,
                            vm);
    vm = NULL;
    ret = 0;

cleanup:
    VIR_FREE(name);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemudDomainUndefine(virDomainPtr dom)
{
    return qemuDomainUndefineFlags(dom, 0);
}

static int
qemuDomainAttachDeviceDiskLive(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk = dev->data.disk;
    virCgroupPtr cgroup = NULL;
    int ret = -1;

    if (disk->driverName != NULL && !STREQ(disk->driverName, "qemu")) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unsupported driver name '%s' for disk '%s'"),
                        disk->driverName, disk->src);
        goto end;
    }

    if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unable to find cgroup for %s"),
                            vm->def->name);
            goto end;
        }
        if (qemuSetupDiskCgroup(driver, vm, cgroup, disk) < 0)
            goto end;
    }
    switch (disk->device)  {
    case VIR_DOMAIN_DISK_DEVICE_CDROM:
    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        ret = qemuDomainChangeEjectableMedia(driver, vm, disk, false);
        break;
    case VIR_DOMAIN_DISK_DEVICE_DISK:
        if (disk->bus == VIR_DOMAIN_DISK_BUS_USB)
            ret = qemuDomainAttachUsbMassstorageDevice(driver, vm,
                                                       disk);
        else if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
            ret = qemuDomainAttachPciDiskDevice(driver, vm, disk);
        else if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI)
            ret = qemuDomainAttachSCSIDisk(driver, vm, disk);
        else
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("disk bus '%s' cannot be hotplugged."),
                            virDomainDiskBusTypeToString(disk->bus));
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("disk device type '%s' cannot be hotplugged"),
                        virDomainDiskDeviceTypeToString(disk->device));
        break;
    }

    if (ret != 0 && cgroup) {
        if (qemuTeardownDiskCgroup(driver, vm, cgroup, disk) < 0)
            VIR_WARN("Failed to teardown cgroup for disk path %s",
                     NULLSTR(disk->src));
    }
end:
    if (cgroup)
        virCgroupFree(&cgroup);
    return ret;
}

static int
qemuDomainAttachDeviceControllerLive(struct qemud_driver *driver,
                                     virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virDomainControllerDefPtr cont = dev->data.controller;
    int ret = -1;

    switch (cont->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        ret = qemuDomainAttachPciControllerDevice(driver, vm, cont);
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("disk controller bus '%s' cannot be hotplugged."),
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
    struct qemud_driver *driver = dom->conn->privateData;
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        qemuDomainObjCheckDiskTaint(driver, vm, dev->data.disk, -1);
        ret = qemuDomainAttachDeviceDiskLive(driver, vm, dev);
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

    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("device type '%s' cannot be attached"),
                        virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
qemuDomainDetachDeviceDiskLive(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk = dev->data.disk;
    int ret = -1;

    switch (disk->device) {
    case VIR_DOMAIN_DISK_DEVICE_DISK:
        if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
            ret = qemuDomainDetachPciDiskDevice(driver, vm, dev);
        else if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI)
            ret =  qemuDomainDetachDiskDevice(driver, vm, dev);
        else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB)
            ret = qemuDomainDetachDiskDevice(driver, vm, dev);
        else
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("This type of disk cannot be hot unplugged"));
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("device type '%s' cannot be detached"),
                        virDomainDeviceTypeToString(dev->type));
        break;
    }
    return ret;
}

static int
qemuDomainDetachDeviceControllerLive(struct qemud_driver *driver,
                                     virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virDomainControllerDefPtr cont = dev->data.controller;
    int ret = -1;

    switch (cont->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        ret = qemuDomainDetachPciControllerDevice(driver, vm, dev);
        break;
    default :
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("disk controller bus '%s' cannot be hotunplugged."),
                        virDomainControllerTypeToString(cont->type));
    }
    return ret;
}

static int
qemuDomainDetachDeviceLive(virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev,
                           virDomainPtr dom)
{
    struct qemud_driver *driver = dom->conn->privateData;
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
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        "%s", _("This type of device cannot be hot unplugged"));
        break;
    }

    return ret;
}

static int
qemuDomainChangeDiskMediaLive(virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev,
                              struct qemud_driver *driver,
                              bool force)
{
    virDomainDiskDefPtr disk = dev->data.disk;
    virCgroupPtr cgroup = NULL;
    int ret = -1;

    if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        if (virCgroupForDomain(driver->cgroup,
                               vm->def->name, &cgroup, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unable to find cgroup for %s"),
                            vm->def->name);
            goto end;
        }
        if (qemuSetupDiskCgroup(driver, vm, cgroup, disk) < 0)
            goto end;
    }

    switch (disk->device) {
    case VIR_DOMAIN_DISK_DEVICE_CDROM:
    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        ret = qemuDomainChangeEjectableMedia(driver, vm, disk, force);
        if (ret == 0)
            dev->data.disk = NULL;
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("disk bus '%s' cannot be updated."),
                        virDomainDiskBusTypeToString(disk->bus));
        break;
    }

    if (ret != 0 && cgroup) {
        if (qemuTeardownDiskCgroup(driver, vm, cgroup, disk) < 0)
             VIR_WARN("Failed to teardown cgroup for disk path %s",
                      NULLSTR(disk->src));
    }
end:
    if (cgroup)
        virCgroupFree(&cgroup);
    return ret;
}

static int
qemuDomainUpdateDeviceLive(virDomainObjPtr vm,
                           virDomainDeviceDefPtr dev,
                           virDomainPtr dom,
                           bool force)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        ret = qemuDomainChangeDiskMediaLive(vm, dev, driver, force);
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        ret = qemuDomainChangeGraphics(driver, vm, dev->data.graphics);
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("device type '%s' cannot be updated"),
                        virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
qemuDomainAttachDeviceConfig(virDomainDefPtr vmdef,
                             virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;
    virDomainNetDefPtr net;
    virDomainLeaseDefPtr lease;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (virDomainDiskIndexByName(vmdef, disk->dst) >= 0) {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("target %s already exists."), disk->dst);
            return -1;
        }
        if (virDomainDiskInsert(vmdef, disk)) {
            virReportOOMError();
            return -1;
        }
        /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
        dev->data.disk = NULL;
        if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            if (virDomainDefAddImplicitControllers(vmdef) < 0)
                return -1;
        if (qemuDomainAssignPCIAddresses(vmdef) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if (virDomainNetIndexByMac(vmdef, net->mac) >= 0) {
            char macbuf[VIR_MAC_STRING_BUFLEN];
            virFormatMacAddr(net->mac, macbuf);
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("mac %s already exists"), macbuf);
            return -1;
        }
        if (virDomainNetInsert(vmdef, net)) {
            virReportOOMError();
            return -1;
        }
        dev->data.net = NULL;
        if (qemuDomainAssignPCIAddresses(vmdef) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
        lease = dev->data.lease;
        if (virDomainLeaseIndex(vmdef, lease) >= 0) {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("Lease %s in lockspace %s already exists"),
                            lease->key, NULLSTR(lease->lockspace));
            return -1;
        }
        if (virDomainLeaseInsert(vmdef, lease) < 0)
            return -1;

        /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
        dev->data.lease = NULL;
        break;

    default:
         qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("persistent attach of device is not supported"));
         return -1;
    }
    return 0;
}


static int
qemuDomainDetachDeviceConfig(virDomainDefPtr vmdef,
                             virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;
    virDomainNetDefPtr net;
    virDomainLeaseDefPtr lease;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (virDomainDiskRemoveByName(vmdef, disk->dst)) {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("no target device %s"), disk->dst);
            return -1;
        }
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if (virDomainNetRemoveByMac(vmdef, net->mac)) {
            char macbuf[VIR_MAC_STRING_BUFLEN];

            virFormatMacAddr(net->mac, macbuf);
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("no nic of mac %s"), macbuf);
            return -1;
        }
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
        lease = dev->data.lease;
        if (virDomainLeaseRemove(vmdef, lease) < 0) {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("Lease %s in lockspace %s does not exist"),
                            lease->key, NULLSTR(lease->lockspace));
            return -1;
        }
        break;

    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("persistent detach of device is not supported"));
        return -1;
    }
    return 0;
}

static int
qemuDomainUpdateDeviceConfig(virDomainDefPtr vmdef,
                             virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr orig, disk;
    int pos;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        pos = virDomainDiskIndexByName(vmdef, disk->dst);
        if (pos < 0) {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("target %s doesn't exists."), disk->dst);
            return -1;
        }
        orig = vmdef->disks[pos];
        if (!(orig->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
            !(orig->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)) {
            qemuReportError(VIR_ERR_INVALID_ARG,
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
        if (disk->driverType) {
            VIR_FREE(orig->driverType);
            orig->driverType = disk->driverType;
            disk->driverType = NULL;
        }
        disk->src = NULL;
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                         _("persistent update of device is not supported"));
        return -1;
    }
    return 0;
}

/* Actions for qemuDomainModifyDeviceFlags */
enum {
    QEMU_DEVICE_ATTACH,
    QEMU_DEVICE_DETACH,
    QEMU_DEVICE_UPDATE,
};


static int
qemuDomainModifyDeviceFlags(virDomainPtr dom, const char *xml,
                            unsigned int flags, int action)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    bool force = (flags & VIR_DOMAIN_DEVICE_MODIFY_FORCE) != 0;
    int ret = -1;
    unsigned int affect;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  (action == QEMU_DEVICE_UPDATE ?
                   VIR_DOMAIN_DEVICE_MODIFY_FORCE : 0), -1);

    affect = flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s",
                            _("cannot do live update a device on "
                              "inactive domain"));
            goto endjob;
        }
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) && !vm->persistent) {
         qemuReportError(VIR_ERR_OPERATION_INVALID,
                         "%s", _("cannot modify device on transient domain"));
         goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        dev = virDomainDeviceDefParse(driver->caps, vm->def, xml,
                                      VIR_DOMAIN_XML_INACTIVE);
        if (dev == NULL)
            goto endjob;

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(driver->caps, vm);
        if (!vmdef)
            goto endjob;
        switch (action) {
        case QEMU_DEVICE_ATTACH:
            ret = qemuDomainAttachDeviceConfig(vmdef, dev);
            break;
        case QEMU_DEVICE_DETACH:
            ret = qemuDomainDetachDeviceConfig(vmdef, dev);
            break;
        case QEMU_DEVICE_UPDATE:
            ret = qemuDomainUpdateDeviceConfig(vmdef, dev);
            break;
        default:
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unknown domain modify action %d"), action);
            break;
        }

        if (ret == -1)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        dev = virDomainDeviceDefParse(driver->caps, vm->def, xml,
                                      VIR_DOMAIN_XML_INACTIVE);
        if (dev == NULL) {
            ret = -1;
            goto endjob;
        }

        switch (action) {
        case QEMU_DEVICE_ATTACH:
            ret = qemuDomainAttachDeviceLive(vm, dev, dom);
            break;
        case QEMU_DEVICE_DETACH:
            ret = qemuDomainDetachDeviceLive(vm, dev, dom);
            break;
        case QEMU_DEVICE_UPDATE:
            ret = qemuDomainUpdateDeviceLive(vm, dev, dom, force);
            break;
        default:
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unknown domain modify action %d"), action);
            ret = -1;
            break;
        }

        if (ret == -1)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(driver->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false);
            vmdef = NULL;
        }
    }

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags)
{
    return qemuDomainModifyDeviceFlags(dom, xml, flags, QEMU_DEVICE_ATTACH);
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
    return qemuDomainModifyDeviceFlags(dom, xml, flags, QEMU_DEVICE_UPDATE);
}

static int qemuDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags)
{
    return qemuDomainModifyDeviceFlags(dom, xml, flags, QEMU_DEVICE_DETACH);
}

static int qemuDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    return qemuDomainDetachDeviceFlags(dom, xml,
                                       VIR_DOMAIN_AFFECT_LIVE);
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
        qemuReportError(VIR_ERR_OPERATION_INVALID,
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
            if (virFileMakePath(driver->autostartDir) < 0) {
                virReportSystemError(errno,
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


/*
 * check whether the host supports CFS bandwidth
 *
 * Return 1 when CFS bandwidth is supported, 0 when CFS bandwidth is not
 * supported, -1 on error.
 */
static int qemuGetCpuBWStatus(virCgroupPtr cgroup)
{
    char *cfs_period_path = NULL;
    int ret = -1;

    if (!cgroup)
        return 0;

    if (virCgroupPathOfController(cgroup, VIR_CGROUP_CONTROLLER_CPU,
                                  "cpu.cfs_period_us", &cfs_period_path) < 0) {
        VIR_INFO("cannot get the path of cgroup CPU controller");
        ret = 0;
        goto cleanup;
    }

    if (access(cfs_period_path, F_OK) < 0) {
        ret = 0;
    } else {
        ret = 1;
    }

cleanup:
    VIR_FREE(cfs_period_path);
    return ret;
}


static char *qemuGetSchedulerType(virDomainPtr dom,
                                  int *nparams)
{
    struct qemud_driver *driver = dom->conn->privateData;
    char *ret = NULL;
    int rc;

    qemuDriverLock(driver);
    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (nparams) {
        rc = qemuGetCpuBWStatus(driver->cgroup);
        if (rc < 0)
            goto cleanup;
        else if (rc == 0)
            *nparams = 1;
        else
            *nparams = 3;
    }

    ret = strdup("posix");
    if (!ret)
        virReportOOMError();

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainSetBlkioParameters(virDomainPtr dom,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    bool isActive;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    qemuDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!isActive) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto cleanup;
        }

        if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
            qemuReportError(VIR_ERR_NO_SUPPORT, _("blkio cgroup isn't mounted"));
            goto cleanup;
        }

        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find cgroup for domain %s"), vm->def->name);
            goto cleanup;
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot change persistent config of a transient domain"));
            goto cleanup;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto cleanup;
    }

    ret = 0;
    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                int rc;
                if (param->type != VIR_TYPED_PARAM_UINT) {
                    qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                    _("invalid type for blkio weight tunable, expected a 'unsigned int'"));
                    ret = -1;
                    continue;
                }

                if (params[i].value.ui > 1000 || params[i].value.ui < 100) {
                    qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                    _("out of blkio weight range."));
                    ret = -1;
                    continue;
                }

                rc = virCgroupSetBlkioWeight(group, params[i].value.ui);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to set blkio weight tunable"));
                    ret = -1;
                }
            } else {
                qemuReportError(VIR_ERR_INVALID_ARG,
                                _("Parameter `%s' not supported"), param->field);
                ret = -1;
            }
        }
    } else if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                if (param->type != VIR_TYPED_PARAM_UINT) {
                    qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                    _("invalid type for blkio weight tunable, expected a 'unsigned int'"));
                    ret = -1;
                    continue;
                }

                if (params[i].value.ui > 1000 || params[i].value.ui < 100) {
                    qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                    _("out of blkio weight range."));
                    ret = -1;
                    continue;
                }

                persistentDef->blkio.weight = params[i].value.ui;
            } else {
                qemuReportError(VIR_ERR_INVALID_ARG,
                                _("Parameter `%s' not supported"), param->field);
                ret = -1;
            }
        }

        if (virDomainSaveConfig(driver->configDir, persistentDef) < 0)
            ret = -1;
    }

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainGetBlkioParameters(virDomainPtr dom,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    unsigned int val;
    int ret = -1;
    int rc;
    bool isActive;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    qemuDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if ((*nparams) == 0) {
        /* Current number of blkio parameters supported by cgroups */
        *nparams = QEMU_NB_BLKIO_PARAM;
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) != QEMU_NB_BLKIO_PARAM) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("Invalid parameter count"));
        goto cleanup;
    }

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!isActive) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto cleanup;
        }

        if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
            qemuReportError(VIR_ERR_NO_SUPPORT, _("blkio cgroup isn't mounted"));
            goto cleanup;
        }

        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find cgroup for domain %s"), vm->def->name);
            goto cleanup;
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot change persistent config of a transient domain"));
            goto cleanup;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        for (i = 0; i < *nparams; i++) {
            virTypedParameterPtr param = &params[i];
            val = 0;
            param->value.ui = 0;
            param->type = VIR_TYPED_PARAM_UINT;

            switch (i) {
            case 0: /* fill blkio weight here */
                rc = virCgroupGetBlkioWeight(group, &val);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to get blkio weight"));
                    goto cleanup;
                }
                if (virStrcpyStatic(param->field, VIR_DOMAIN_BLKIO_WEIGHT) == NULL) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("Field blkio weight too long for destination"));
                    goto cleanup;
                }
                param->value.ui = val;
                break;

            default:
                break;
                /* should not hit here */
            }
        }
    } else if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        for (i = 0; i < *nparams; i++) {
            virTypedParameterPtr param = &params[i];
            val = 0;
            param->value.ui = 0;
            param->type = VIR_TYPED_PARAM_UINT;

            switch (i) {
            case 0: /* fill blkio weight here */
                if (virStrcpyStatic(param->field, VIR_DOMAIN_BLKIO_WEIGHT) == NULL) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("Field blkio weight too long for destination"));
                    goto cleanup;
                }
                param->value.ui = persistentDef->blkio.weight;
                break;

            default:
                break;
                /* should not hit here */
            }
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

static int qemuDomainSetMemoryParameters(virDomainPtr dom,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virDomainDefPtr persistentDef = NULL;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    bool isActive;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    qemuDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!isActive) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto cleanup;
        }

        if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("cgroup memory controller is not mounted"));
            goto cleanup;
        }

        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find cgroup for domain %s"), vm->def->name);
            goto cleanup;
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot change persistent config of a transient domain"));
            goto cleanup;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto cleanup;
    }

    ret = 0;
    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT)) {
            int rc;
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for memory hard_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = virCgroupSetMemoryHardLimit(group, params[i].value.ul);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to set memory hard_limit tunable"));
                    ret = -1;
                }
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                persistentDef->mem.hard_limit = params[i].value.ul;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT)) {
            int rc;
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for memory soft_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = virCgroupSetMemorySoftLimit(group, params[i].value.ul);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to set memory soft_limit tunable"));
                    ret = -1;
                }
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                persistentDef->mem.soft_limit = params[i].value.ul;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT)) {
            int rc;
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for swap_hard_limit tunable, expected a 'ullong'"));
                ret = -1;
                continue;
            }

            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = virCgroupSetMemSwapHardLimit(group, params[i].value.ul);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to set swap_hard_limit tunable"));
                    ret = -1;
                }
            }
            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                persistentDef->mem.swap_hard_limit = params[i].value.ul;
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

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (virDomainSaveConfig(driver->configDir, persistentDef) < 0)
            ret = -1;
    }

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainGetMemoryParameters(virDomainPtr dom,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    unsigned long long val;
    int ret = -1;
    int rc;
    bool isActive;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    qemuDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!isActive) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto cleanup;
        }

        if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("cgroup memory controller is not mounted"));
            goto cleanup;
        }

        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find cgroup for domain %s"), vm->def->name);
            goto cleanup;
        }
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot change persistent config of a transient domain"));
            goto cleanup;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto cleanup;
    }

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = QEMU_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) < QEMU_NB_MEM_PARAM) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("Invalid parameter count"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        for (i = 0; i < *nparams; i++) {
            virMemoryParameterPtr param = &params[i];
            val = 0;
            param->value.ul = 0;
            param->type = VIR_TYPED_PARAM_ULLONG;

            switch (i) {
            case 0: /* fill memory hard limit here */
                if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT) == NULL) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("Field memory hard limit too long for destination"));
                    goto cleanup;
                }
                param->value.ul = persistentDef->mem.hard_limit;
                break;

            case 1: /* fill memory soft limit here */
                if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT) == NULL) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("Field memory soft limit too long for destination"));
                    goto cleanup;
                }
                param->value.ul = persistentDef->mem.soft_limit;
                break;

            case 2: /* fill swap hard limit here */
                if (virStrcpyStatic(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT) == NULL) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("Field swap hard limit too long for destination"));
                    goto cleanup;
                }
                param->value.ul = persistentDef->mem.swap_hard_limit;
                break;

            default:
                break;
                /* should not hit here */
            }
        }
        goto out;
    }

    for (i = 0; i < QEMU_NB_MEM_PARAM; i++) {
        virTypedParameterPtr param = &params[i];
        val = 0;
        param->value.ul = 0;
        param->type = VIR_TYPED_PARAM_ULLONG;

        /* Coverity does not realize that if we get here, group is set.  */
        sa_assert(group);

        switch (i) {
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
            rc = virCgroupGetMemSwapHardLimit(group, &val);
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

out:
    *nparams = QEMU_NB_MEM_PARAM;
    ret = 0;

cleanup:
    if (group)
        virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemuSetVcpusBWLive(virDomainObjPtr vm, virCgroupPtr cgroup,
                   unsigned long long period, long long quota)
{
    int i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup_vcpu = NULL;
    int rc;
    long long vm_quota = 0;
    long long old_quota = 0;
    unsigned long long old_period = 0;

    if (period == 0 && quota == 0)
        return 0;

    /* Ensure that we can multiply by vcpus without overflowing. */
    if (quota > LLONG_MAX / vm->def->vcpus) {
        virReportSystemError(EINVAL,
                             _("%s"),
                             "Unable to set cpu bandwidth quota");
        goto cleanup;
    }

    if (quota > 0)
        vm_quota = quota * vm->def->vcpus;
    else
        vm_quota = quota;

    rc = virCgroupGetCpuCfsQuota(cgroup, &old_quota);
    if (rc < 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu bandwidth tunable"));
        goto cleanup;
    }

    rc = virCgroupGetCpuCfsPeriod(cgroup, &old_period);
    if (rc < 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu bandwidth period tunable"));
        goto cleanup;
    }

    /*
     * If quota will be changed to a small value, we should modify vcpu's quota
     * first. Otherwise, we should modify vm's quota first.
     *
     * If period will be changed to a small value, we should modify vm's period
     * first. Otherwise, we should modify vcpu's period first.
     *
     * If both quota and period will be changed to a big/small value, we cannot
     * modify period and quota together.
     */
    if ((quota != 0) && (period != 0)) {
        if (((quota > old_quota) && (period > old_period)) ||
            ((quota < old_quota) && (period < old_period))) {
            /* modify period */
            if (qemuSetVcpusBWLive(vm, cgroup, period, 0) < 0)
                goto cleanup;

            /* modify quota */
            if (qemuSetVcpusBWLive(vm, cgroup, 0, quota) < 0)
                goto cleanup;
            return 0;
        }
    }

    if (((vm_quota != 0) && (vm_quota > old_quota)) ||
        ((period != 0) && (period < old_period)))
        /* Set cpu bandwidth for the vm */
        if (qemuSetupCgroupVcpuBW(cgroup, period, vm_quota) < 0)
            goto cleanup;

    /* If we does not know VCPU<->PID mapping or all vcpu runs in the same
     * thread, we cannot control each vcpu. So we only modify cpu bandwidth
     * when each vcpu has a separated thread.
     */
    if (priv->nvcpupids != 0 && priv->vcpupids[0] != vm->pid) {
        for (i = 0; i < priv->nvcpupids; i++) {
            rc = virCgroupForVcpu(cgroup, i, &cgroup_vcpu, 0);
            if (rc < 0) {
                virReportSystemError(-rc,
                                     _("Unable to find vcpu cgroup for %s(vcpu:"
                                       " %d)"),
                                     vm->def->name, i);
                goto cleanup;
            }

            if (qemuSetupCgroupVcpuBW(cgroup_vcpu, period, quota) < 0)
                goto cleanup;

            virCgroupFree(&cgroup_vcpu);
        }
    }

    if (((vm_quota != 0) && (vm_quota <= old_quota)) ||
        ((period != 0) && (period >= old_period)))
        /* Set cpu bandwidth for the vm */
        if (qemuSetupCgroupVcpuBW(cgroup, period, vm_quota) < 0)
            goto cleanup;

    return 0;

cleanup:
    virCgroupFree(&cgroup_vcpu);
    return -1;
}

static int qemuSetSchedulerParametersFlags(virDomainPtr dom,
                                           virTypedParameterPtr params,
                                           int nparams,
                                           unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    int ret = -1;
    bool isActive;
    int rc;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    qemuDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot change persistent config of a transient domain"));
            goto cleanup;
        }

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(driver->caps, vm);
        if (!vmdef)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!isActive) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("domain is not running"));
            goto cleanup;
        }

        if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("cgroup CPU controller is not mounted"));
            goto cleanup;
        }
        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find cgroup for domain %s"),
                            vm->def->name);
            goto cleanup;
        }
    }

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, "cpu_shares")) {
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for cpu_shares tunable, expected a 'ullong'"));
                goto cleanup;
            }

            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = virCgroupSetCpuShares(group, params[i].value.ul);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to set cpu shares tunable"));
                    goto cleanup;
                }

                vm->def->cputune.shares = params[i].value.ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.shares = params[i].value.ul;
            }
        } else if (STREQ(param->field, "vcpu_period")) {
            if (param->type != VIR_TYPED_PARAM_ULLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for vcpu_period tunable,"
                                  " expected a 'ullong'"));
                goto cleanup;
            }

            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = qemuSetVcpusBWLive(vm, group, params[i].value.ul, 0);
                if (rc != 0)
                    goto cleanup;

                if (params[i].value.ul)
                    vm->def->cputune.period = params[i].value.ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.period = params[i].value.ul;
            }
        } else if (STREQ(param->field, "vcpu_quota")) {
            if (param->type != VIR_TYPED_PARAM_LLONG) {
                qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("invalid type for vcpu_quota tunable,"
                                  " expected a 'llong'"));
                goto cleanup;
            }

            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = qemuSetVcpusBWLive(vm, group, 0, params[i].value.l);
                if (rc != 0)
                    goto cleanup;

                if (params[i].value.l)
                    vm->def->cputune.quota = params[i].value.l;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.quota = params[i].value.l;
            }
        } else {
            qemuReportError(VIR_ERR_INVALID_ARG,
                            _("Invalid parameter `%s'"), param->field);
            goto cleanup;
        }
    }

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;


    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        rc = virDomainSaveConfig(driver->configDir, vmdef);
        if (rc < 0)
            goto cleanup;

        virDomainObjAssignDef(vm, vmdef, false);
        vmdef = NULL;
    }

    ret = 0;

cleanup:
    virDomainDefFree(vmdef);
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuSetSchedulerParameters(virDomainPtr dom,
                                      virTypedParameterPtr params,
                                      int nparams)
{
    return qemuSetSchedulerParametersFlags(dom,
                                           params,
                                           nparams,
                                           VIR_DOMAIN_AFFECT_LIVE);
}

static int
qemuGetVcpuBWLive(virCgroupPtr cgroup, unsigned long long *period,
                  long long *quota)
{
    int rc;

    rc = virCgroupGetCpuCfsPeriod(cgroup, period);
    if (rc < 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu bandwidth period tunable"));
        return -1;
    }

    rc = virCgroupGetCpuCfsQuota(cgroup, quota);
    if (rc < 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu bandwidth tunable"));
        return -1;
    }

    return 0;
}

static int
qemuGetVcpusBWLive(virDomainObjPtr vm, virCgroupPtr cgroup,
                   unsigned long long *period, long long *quota)
{
    virCgroupPtr cgroup_vcpu = NULL;
    qemuDomainObjPrivatePtr priv = NULL;
    int rc;
    int ret = -1;

    priv = vm->privateData;
    if (priv->nvcpupids == 0 || priv->vcpupids[0] == vm->pid) {
        /* We do not create sub dir for each vcpu */
        rc = qemuGetVcpuBWLive(cgroup, period, quota);
        if (rc < 0)
            goto cleanup;

        if (*quota > 0)
            *quota /= vm->def->vcpus;
        goto out;
    }

    /* get period and quota for vcpu0 */
    rc = virCgroupForVcpu(cgroup, 0, &cgroup_vcpu, 0);
    if (!cgroup_vcpu) {
        virReportSystemError(-rc,
                             _("Unable to find vcpu cgroup for %s(vcpu: 0)"),
                             vm->def->name);
        goto cleanup;
    }

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
qemuGetSchedulerParametersFlags(virDomainPtr dom,
                                virTypedParameterPtr params,
                                int *nparams,
                                unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long long shares;
    unsigned long long period;
    long long quota;
    int ret = -1;
    int rc;
    bool isActive;
    bool cpu_bw_status = false;
    int saved_nparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    qemuDriverLock(driver);

    if ((flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG)) ==
        (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG)) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("cannot query live and config together"));
        goto cleanup;
    }

    if (*nparams < 1) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("Invalid parameter count"));
        goto cleanup;
    }

    if (*nparams > 1) {
        rc = qemuGetCpuBWStatus(driver->cgroup);
        if (rc < 0)
            goto cleanup;
        cpu_bw_status = !!rc;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot query persistent config of a transient domain"));
            goto cleanup;
        }

        if (isActive) {
            virDomainDefPtr persistentDef;

            persistentDef = virDomainObjGetPersistentDef(driver->caps, vm);
            if (!persistentDef) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("can't get persistentDef"));
                goto cleanup;
            }
            shares = persistentDef->cputune.shares;
            if (*nparams > 1 && cpu_bw_status) {
                period = persistentDef->cputune.period;
                quota = persistentDef->cputune.quota;
            }
        } else {
            shares = vm->def->cputune.shares;
            if (*nparams > 1 && cpu_bw_status) {
                period = vm->def->cputune.period;
                quota = vm->def->cputune.quota;
            }
        }
        goto out;
    }

    if (!isActive) {
        qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("domain is not running"));
        goto cleanup;
    }

    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    rc = virCgroupGetCpuShares(group, &shares);
    if (rc != 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu shares tunable"));
        goto cleanup;
    }

    if (*nparams > 1 && cpu_bw_status) {
        rc = qemuGetVcpusBWLive(vm, group, &period, &quota);
        if (rc != 0)
            goto cleanup;
    }
out:
    params[0].value.ul = shares;
    params[0].type = VIR_TYPED_PARAM_ULLONG;
    if (virStrcpyStatic(params[0].field, "cpu_shares") == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Field cpu_shares too long for destination"));
        goto cleanup;
    }

    saved_nparams++;

    if (cpu_bw_status) {
        if (*nparams > saved_nparams) {
            params[1].value.ul = period;
            params[1].type = VIR_TYPED_PARAM_ULLONG;
            if (virStrcpyStatic(params[1].field, "vcpu_period") == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s",
                                _("Field vcpu_period too long for destination"));
                goto cleanup;
            }
            saved_nparams++;
        }

        if (*nparams > saved_nparams) {
            params[2].value.ul = quota;
            params[2].type = VIR_TYPED_PARAM_LLONG;
            if (virStrcpyStatic(params[2].field, "vcpu_quota") == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s",
                                _("Field vcpu_quota too long for destination"));
                goto cleanup;
            }
            saved_nparams++;
        }
    }

    *nparams = saved_nparams;

    ret = 0;

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemuGetSchedulerParameters(virDomainPtr dom,
                           virTypedParameterPtr params,
                           int *nparams)
{
    return qemuGetSchedulerParametersFlags(dom, params, nparams,
                                           VIR_DOMAIN_AFFECT_CURRENT);
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
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("invalid path: %s"), path);
        goto cleanup;
    }

    if (!disk->info.alias) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("missing disk device alias name for %s"), disk->dst);
        goto cleanup;
    }

    priv = vm->privateData;
    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorGetBlockStatsInfo(priv->mon,
                                       disk->info.alias,
                                       &stats->rd_req,
                                       &stats->rd_bytes,
                                       &stats->wr_req,
                                       &stats->wr_bytes,
                                       &stats->errs);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
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
{
    qemuReportError(VIR_ERR_NO_SUPPORT,
                    "%s", __FUNCTION__);
    return -1;
}
#endif

static int
qemudDomainMemoryStats (virDomainPtr dom,
                        struct _virDomainMemoryStat *stats,
                        unsigned int nr_stats,
                        unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned int ret = -1;

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

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorGetMemoryStats(priv->mon, stats, nr_stats);
        qemuDomainObjExitMonitor(driver, vm);
    } else {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
    }

    if (qemuDomainObjEndJob(driver, vm) == 0)
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
                      unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int fd = -1, ret = -1, i;

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
    qemuDomainObjPrivatePtr priv;

    virCheckFlags(VIR_MEMORY_VIRTUAL | VIR_MEMORY_PHYSICAL, -1);

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

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
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

    virSecurityManagerSetSavedStateLabel(qemu_driver->securityManager, vm, tmp);

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
    if (saferead (fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError(errno,
                             _("failed to read temporary file "
                               "created with template %s"), tmp);
        goto endjob;
    }

    ret = 0;

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    VIR_FORCE_CLOSE(fd);
    if (tmp)
        unlink(tmp);
    VIR_FREE(tmp);
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
    virStorageFileMetadata *meta = NULL;
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

    if (VIR_ALLOC(meta) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virStorageFileGetMetadataFromFD(path, fd,
                                        format,
                                        meta) < 0)
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

        if (qemuDomainObjEndJob(driver, vm) == 0)
            vm = NULL;
    } else {
        ret = 0;
    }

cleanup:
    virStorageFileFreeMetadata(meta);
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
    ret = virDomainEventCallbackListAdd(conn,
                                        driver->domainEventState->callbacks,
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
    ret = virDomainEventStateDeregister(conn,
                                        driver->domainEventState,
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
                                          driver->domainEventState->callbacks,
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
    ret = virDomainEventStateDeregisterAny(conn,
                                           driver->domainEventState,
                                           callbackID);
    qemuDriverUnlock(driver);

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
qemudDomainMigratePrepareTunnel(virConnectPtr dconn,
                                virStreamPtr st,
                                unsigned long flags,
                                const char *dname,
                                unsigned long resource ATTRIBUTE_UNUSED,
                                const char *dom_xml)
{
    struct qemud_driver *driver = dconn->privateData;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

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

    if (virLockManagerPluginUsesState(driver->lockManager)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot use migrate v2 protocol with lock manager %s"),
                        virLockManagerPluginGetName(driver->lockManager));
        goto cleanup;
    }

    ret = qemuMigrationPrepareTunnel(driver, dconn,
                                     NULL, 0, NULL, NULL, /* No cookies in v2 */
                                     st, dname, dom_xml);

cleanup:
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
    struct qemud_driver *driver = dconn->privateData;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    *uri_out = NULL;

    qemuDriverLock(driver);

    if (virLockManagerPluginUsesState(driver->lockManager)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot use migrate v2 protocol with lock manager %s"),
                        virLockManagerPluginGetName(driver->lockManager));
        goto cleanup;
    }

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

    /* Do not use cookies in v2 protocol, since the cookie
     * length was not sufficiently large, causing failures
     * migrating between old & new libvirtd
     */
    ret = qemuMigrationPrepareDirect(driver, dconn,
                                     NULL, 0, NULL, NULL, /* No cookies */
                                     uri_in, uri_out,
                                     dname, dom_xml);

cleanup:
    qemuDriverUnlock(driver);
    return ret;
}


/* Perform is the second step, and it runs on the source host. */
static int
qemudDomainMigratePerform (virDomainPtr dom,
                           const char *cookie,
                           int cookielen,
                           const char *uri,
                           unsigned long flags,
                           const char *dname,
                           unsigned long resource)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    const char *dconnuri = NULL;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    qemuDriverLock(driver);
    if (virLockManagerPluginUsesState(driver->lockManager)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot use migrate v2 protocol with lock manager %s"),
                        virLockManagerPluginGetName(driver->lockManager));
        goto cleanup;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
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
                               NULL, dconnuri, uri, cookie, cookielen,
                               NULL, NULL, /* No output cookies in v2 */
                               flags, dname, resource, false);

cleanup:
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

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);

    qemuDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dname);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching name '%s'"), dname);
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
    qemuDriverUnlock(driver);
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
                        const char *dname ATTRIBUTE_UNUSED,
                        unsigned long resource ATTRIBUTE_UNUSED)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm;
    char *xml = NULL;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto cleanup;
    } else {
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
            goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    if (!(xml = qemuMigrationBegin(driver, vm, xmlin,
                                   cookieout, cookieoutlen)))
        goto endjob;

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        /* We keep the job active across API calls until the confirm() call.
         * This prevents any other APIs being invoked while migration is taking
         * place.
         */
        if (qemuMigrationJobContinue(vm) == 0) {
            vm = NULL;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("domain disappeared"));
            VIR_FREE(xml);
            if (cookieout)
                VIR_FREE(*cookieout);
        }
    } else {
        goto endjob;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return xml;

endjob:
    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobFinish(driver, vm) == 0)
            vm = NULL;
    } else {
        if (qemuDomainObjEndJob(driver, vm) == 0)
            vm = NULL;
    }
    goto cleanup;
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
    struct qemud_driver *driver = dconn->privateData;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

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

    ret = qemuMigrationPrepareDirect(driver, dconn,
                                     cookiein, cookieinlen,
                                     cookieout, cookieoutlen,
                                     uri_in, uri_out,
                                     dname, dom_xml);

cleanup:
    qemuDriverUnlock(driver);
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
    struct qemud_driver *driver = dconn->privateData;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

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

    qemuDriverLock(driver);
    ret = qemuMigrationPrepareTunnel(driver, dconn,
                                     cookiein, cookieinlen,
                                     cookieout, cookieoutlen,
                                     st, dname, dom_xml);
    qemuDriverUnlock(driver);

cleanup:
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
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = qemuMigrationPerform(driver, dom->conn, vm, xmlin,
                               dconnuri, uri, cookiein, cookieinlen,
                               cookieout, cookieoutlen,
                               flags, dname, resource, true);

cleanup:
    qemuDriverUnlock(driver);
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
    struct qemud_driver *driver = dconn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    virCheckFlags(QEMU_MIGRATION_FLAGS, NULL);

    qemuDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, dname);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching name '%s'"), dname);
        goto cleanup;
    }

    dom = qemuMigrationFinish(driver, dconn, vm,
                              cookiein, cookieinlen,
                              cookieout, cookieoutlen,
                              flags, cancelled, true);

cleanup:
    qemuDriverUnlock(driver);
    return dom;
}

static int
qemuDomainMigrateConfirm3(virDomainPtr domain,
                          const char *cookiein,
                          int cookieinlen,
                          unsigned long flags,
                          int cancelled)
{
    struct qemud_driver *driver = domain->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    enum qemuMigrationJobPhase phase;

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, domain->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT))
        goto cleanup;

    if (cancelled)
        phase = QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED;
    else
        phase = QEMU_MIGRATION_PHASE_CONFIRM3;

    qemuMigrationJobStartPhase(driver, vm, phase);

    ret = qemuMigrationConfirm(driver, domain->conn, vm,
                               cookiein, cookieinlen,
                               flags, cancelled);

    if (qemuMigrationJobFinish(driver, vm) == 0) {
        vm = NULL;
    } else if (!virDomainObjIsActive(vm) &&
               (!vm->persistent || (flags & VIR_MIGRATE_UNDEFINE_SOURCE))) {
        if (flags & VIR_MIGRATE_UNDEFINE_SOURCE)
            virDomainDeleteConfig(driver->configDir, driver->autostartDir, vm);
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
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

    pciDeviceReAttachInit(pci);

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
               unsigned int flags)
{
    struct qemud_driver *driver = conn->privateData;
    int ret = VIR_CPU_COMPARE_ERROR;

    virCheckFlags(0, VIR_CPU_COMPARE_ERROR);

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
                unsigned int flags)
{
    char *cpu;

    virCheckFlags(0, NULL);

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
        if (priv->job.asyncJob) {
            memcpy(info, &priv->job.info, sizeof(*info));

            /* Refresh elapsed time again just to ensure it
             * is fully updated. This is primarily for benefit
             * of incoming migration which we don't currently
             * monitor actively in the background thread
             */
            if (virTimeMs(&info->timeElapsed) < 0)
                goto cleanup;
            info->timeElapsed -= priv->job.start;
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

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_ABORT) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (!priv->job.asyncJob) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("no job is active on the domain"));
        goto endjob;
    } else if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_IN) {
        qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot abort incoming migration;"
                          " use virDomainDestroy instead"));
        goto endjob;
    }

    VIR_DEBUG("Cancelling job at client request");
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorMigrateCancel(priv->mon);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

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
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MIGRATION_OP) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (priv->job.asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not being migrated"));
        goto endjob;
    }

    VIR_DEBUG("Setting migration downtime to %llums", downtime);
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSetMigrationDowntime(priv->mon, downtime);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
qemuDomainMigrateSetMaxSpeed(virDomainPtr dom,
                             unsigned long bandwidth,
                             unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    qemuDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    qemuDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    qemuDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MIGRATION_OP) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (priv->job.asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not being migrated"));
        goto endjob;
    }

    VIR_DEBUG("Setting migration bandwidth to %luMbs", bandwidth);
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorSetMigrationSpeed(priv->mon, bandwidth);
    qemuDomainObjExitMonitor(driver, vm);

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
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
    if (virFileMakePath(snapDir) < 0) {
        virReportSystemError(errno, _("cannot create snapshot directory '%s'"),
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

/* The domain is expected to be locked and inactive. */
static int
qemuDomainSnapshotCreateInactive(virDomainObjPtr vm,
                                 virDomainSnapshotObjPtr snap)
{
    const char *qemuimgarg[] = { NULL, "snapshot", "-c", NULL, NULL, NULL };
    int ret = -1;
    int i;

    qemuimgarg[0] = qemuFindQemuImgBinary();
    if (qemuimgarg[0] == NULL) {
        /* qemuFindQemuImgBinary set the error */
        goto cleanup;
    }

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
                                _("Disk device '%s' does not support"
                                  " snapshotting"),
                                vm->def->disks[i]->info.alias);
                goto cleanup;
            }

            qemuimgarg[4] = vm->def->disks[i]->src;

            if (virRun(qemuimgarg, NULL) < 0)
                goto cleanup;
        }
    }

    ret = 0;

cleanup:
    VIR_FREE(qemuimgarg[0]);
    return ret;
}

/* The domain is expected to be locked and active. */
static int
qemuDomainSnapshotCreateActive(virConnectPtr conn,
                               struct qemud_driver *driver,
                               virDomainObjPtr *vmptr,
                               virDomainSnapshotObjPtr snap)
{
    virDomainObjPtr vm = *vmptr;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool resume = false;
    int ret = -1;

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        return -1;

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
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto cleanup;
        }
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorCreateSnapshot(priv->mon, snap->def->name);
    qemuDomainObjExitMonitorWithDriver(driver, vm);

cleanup:
    if (resume && virDomainObjIsActive(vm) &&
        qemuProcessStartCPUs(driver, vm, conn,
                             VIR_DOMAIN_RUNNING_UNPAUSED,
                             QEMU_ASYNC_JOB_NONE) < 0 &&
        virGetLastError() == NULL) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("resuming after snapshot failed"));
    }

    if (qemuDomainObjEndJob(driver, vm) == 0)
        *vmptr = NULL;

    return ret;
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

    snap->def->state = virDomainObjGetState(vm, NULL);

    /* actually do the snapshot */
    if (!virDomainObjIsActive(vm)) {
        if (qemuDomainSnapshotCreateInactive(vm, snap) < 0)
            goto cleanup;
    }
    else {
        if (qemuDomainSnapshotCreateActive(domain->conn, driver,
                                           &vm, snap) < 0)
            goto cleanup;
    }

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

static char *qemuDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
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

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
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

            rc = qemuProcessStart(snapshot->domain->conn, driver, vm, NULL,
                                  false, false, -1, NULL, VIR_VM_OP_CREATE);
            virDomainAuditStart(vm, "from-snapshot", rc >= 0);
            if (qemuDomainSnapshotSetCurrentInactive(vm, driver->snapshotDir) < 0)
                goto endjob;
            if (rc < 0)
                goto endjob;
        }

        if (snap->def->state == VIR_DOMAIN_PAUSED) {
            /* qemu unconditionally starts the domain running again after
             * loadvm, so let's pause it to keep consistency
             * XXX we should have used qemuProcessStart's start_paused instead
             */
            rc = qemuProcessStopCPUs(driver, vm,
                                     VIR_DOMAIN_PAUSED_FROM_SNAPSHOT,
                                     QEMU_ASYNC_JOB_NONE);
            if (rc < 0)
                goto endjob;
        } else {
            virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_FROM_SNAPSHOT);
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
            qemuProcessStop(driver, vm, 0, VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT);
            virDomainAuditStop(vm, "from-snapshot");
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
            if (!vm->persistent) {
                if (qemuDomainObjEndJob(driver, vm) > 0)
                    virDomainRemoveInactive(&driver->domains, vm);
                vm = NULL;
                goto cleanup;
            }
        }

        if (qemuDomainSnapshotSetCurrentActive(vm, driver->snapshotDir) < 0)
            goto endjob;
    }

    ret = 0;

endjob:
    if (vm && qemuDomainObjEndJob(driver, vm) == 0)
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
                                              const void *name ATTRIBUTE_UNUSED,
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
                                   const void *name ATTRIBUTE_UNUSED,
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

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
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
    if (qemuDomainObjEndJob(driver, vm) == 0)
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
    bool hmp;

    virCheckFlags(VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP, -1);

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

    qemuDomainObjTaint(driver, vm, VIR_DOMAIN_TAINT_CUSTOM_MONITOR, -1);

    hmp = !!(flags & VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP);

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorArbitraryCommand(priv->mon, cmd, result, hmp);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (qemuDomainObjEndJob(driver, vm) == 0) {
        vm = NULL;
        goto cleanup;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}


static virDomainPtr qemuDomainAttach(virConnectPtr conn,
                                     unsigned int pid,
                                     unsigned int flags)
{
    struct qemud_driver *driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainPtr dom = NULL;
    virDomainChrSourceDefPtr monConfig = NULL;
    bool monJSON = false;
    char *pidfile;

    virCheckFlags(0, NULL);

    qemuDriverLock(driver);

    if (!(def = qemuParseCommandLinePid(driver->caps, pid,
                                        &pidfile, &monConfig, &monJSON)))
        goto cleanup;

    if (!monConfig) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("No monitor connection for pid %u"),
                        pid);
        goto cleanup;
    }
    if (monConfig->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("Cannot connect to monitor connection of type '%s' for pid %u"),
                        virDomainChrTypeToString(monConfig->type), pid);
        goto cleanup;
    }

    if (!(def->name) &&
        virAsprintf(&def->name, "attach-pid-%u", pid) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (qemudCanonicalizeMachine(driver, def) < 0)
        goto cleanup;

    if (qemuDomainAssignPCIAddresses(def) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, false)))
        goto cleanup;

    def = NULL;

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (qemuProcessAttach(conn, driver, vm, pid,
                          pidfile, monConfig, monJSON) < 0) {
        monConfig = NULL;
        goto endjob;
    }

    monConfig = NULL;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0) {
        vm = NULL;
        goto cleanup;
    }

cleanup:
    virDomainDefFree(def);
    virDomainChrSourceDefFree(monConfig);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    VIR_FREE(pidfile);
    return dom;
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

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("character device %s is not using a PTY"),
                        NULLSTR(devname));
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->source.data.file.path,
                            0, 0, O_RDWR) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static const char *
qemuDiskPathToAlias(virDomainObjPtr vm, const char *path) {
    int i;
    char *ret = NULL;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        if (disk->type != VIR_DOMAIN_DISK_TYPE_BLOCK &&
            disk->type != VIR_DOMAIN_DISK_TYPE_FILE)
            continue;

        if (disk->src != NULL && STREQ(disk->src, path)) {
            if (virAsprintf(&ret, "drive-%s", disk->info.alias) < 0) {
                virReportOOMError();
                return NULL;
            }
            break;
        }
    }

    if (!ret) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("No device found for specified path"));
    }
    return ret;
}

static int
qemuDomainBlockJobImpl(virDomainPtr dom, const char *path,
                       unsigned long bandwidth, virDomainBlockJobInfoPtr info,
                       int mode)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *device = NULL;
    int ret = -1;

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

    device = qemuDiskPathToAlias(vm, path);
    if (!device) {
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    priv = vm->privateData;
    ret = qemuMonitorBlockJob(priv->mon, device, bandwidth, info, mode);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (qemuDomainObjEndJob(driver, vm) == 0) {
        vm = NULL;
        goto cleanup;
    }

cleanup:
    VIR_FREE(device);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int
qemuDomainBlockJobAbort(virDomainPtr dom, const char *path, unsigned int flags)
{
    virCheckFlags(0, -1);
    return qemuDomainBlockJobImpl(dom, path, 0, NULL, BLOCK_JOB_ABORT);
}

static int
qemuDomainGetBlockJobInfo(virDomainPtr dom, const char *path,
                           virDomainBlockJobInfoPtr info, unsigned int flags)
{
    virCheckFlags(0, -1);
    return qemuDomainBlockJobImpl(dom, path, 0, info, BLOCK_JOB_INFO);
}

static int
qemuDomainBlockJobSetSpeed(virDomainPtr dom, const char *path,
                           unsigned long bandwidth, unsigned int flags)
{
    virCheckFlags(0, -1);
    return qemuDomainBlockJobImpl(dom, path, bandwidth, NULL, BLOCK_JOB_SPEED);
}

static int
qemuDomainBlockPull(virDomainPtr dom, const char *path, unsigned long bandwidth,
                    unsigned int flags)
{
    virCheckFlags(0, -1);
    return qemuDomainBlockJobImpl(dom, path, bandwidth, NULL, BLOCK_JOB_PULL);
}

static virDriver qemuDriver = {
    .no = VIR_DRV_QEMU,
    .name = "QEMU",
    .open = qemudOpen, /* 0.2.0 */
    .close = qemudClose, /* 0.2.0 */
    .supports_feature = qemudSupportsFeature, /* 0.5.0 */
    .type = qemudGetType, /* 0.2.0 */
    .version = qemudGetVersion, /* 0.2.0 */
    .getHostname = virGetHostname, /* 0.3.3 */
    .getSysinfo = qemuGetSysinfo, /* 0.8.8 */
    .getMaxVcpus = qemudGetMaxVCPUs, /* 0.2.1 */
    .nodeGetInfo = nodeGetInfo, /* 0.2.0 */
    .getCapabilities = qemudGetCapabilities, /* 0.2.1 */
    .listDomains = qemudListDomains, /* 0.2.0 */
    .numOfDomains = qemudNumDomains, /* 0.2.0 */
    .domainCreateXML = qemudDomainCreate, /* 0.2.0 */
    .domainLookupByID = qemudDomainLookupByID, /* 0.2.0 */
    .domainLookupByUUID = qemudDomainLookupByUUID, /* 0.2.0 */
    .domainLookupByName = qemudDomainLookupByName, /* 0.2.0 */
    .domainSuspend = qemudDomainSuspend, /* 0.2.0 */
    .domainResume = qemudDomainResume, /* 0.2.0 */
    .domainShutdown = qemuDomainShutdown, /* 0.2.0 */
    .domainReboot = qemuDomainReboot, /* 0.9.3 */
    .domainDestroy = qemuDomainDestroy, /* 0.2.0 */
    .domainDestroyFlags = qemuDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = qemudDomainGetOSType, /* 0.2.2 */
    .domainGetMaxMemory = qemudDomainGetMaxMemory, /* 0.4.2 */
    .domainSetMaxMemory = qemudDomainSetMaxMemory, /* 0.4.2 */
    .domainSetMemory = qemudDomainSetMemory, /* 0.4.2 */
    .domainSetMemoryFlags = qemudDomainSetMemoryFlags, /* 0.9.0 */
    .domainSetMemoryParameters = qemuDomainSetMemoryParameters, /* 0.8.5 */
    .domainGetMemoryParameters = qemuDomainGetMemoryParameters, /* 0.8.5 */
    .domainSetBlkioParameters = qemuDomainSetBlkioParameters, /* 0.9.0 */
    .domainGetBlkioParameters = qemuDomainGetBlkioParameters, /* 0.9.0 */
    .domainGetInfo = qemudDomainGetInfo, /* 0.2.0 */
    .domainGetState = qemuDomainGetState, /* 0.9.2 */
    .domainGetControlInfo = qemuDomainGetControlInfo, /* 0.9.3 */
    .domainSave = qemuDomainSave, /* 0.2.0 */
    .domainSaveFlags = qemuDomainSaveFlags, /* 0.9.4 */
    .domainRestore = qemuDomainRestore, /* 0.2.0 */
    .domainRestoreFlags = qemuDomainRestoreFlags, /* 0.9.4 */
    .domainSaveImageGetXMLDesc = qemuDomainSaveImageGetXMLDesc, /* 0.9.4 */
    .domainSaveImageDefineXML = qemuDomainSaveImageDefineXML, /* 0.9.4 */
    .domainCoreDump = qemudDomainCoreDump, /* 0.7.0 */
    .domainScreenshot = qemuDomainScreenshot, /* 0.9.2 */
    .domainSetVcpus = qemuDomainSetVcpus, /* 0.4.4 */
    .domainSetVcpusFlags = qemuDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = qemudDomainGetVcpusFlags, /* 0.8.5 */
    .domainPinVcpu = qemudDomainPinVcpu, /* 0.4.4 */
    .domainPinVcpuFlags = qemudDomainPinVcpuFlags, /* 0.9.3 */
    .domainGetVcpuPinInfo = qemudDomainGetVcpuPinInfo, /* 0.9.3 */
    .domainGetVcpus = qemudDomainGetVcpus, /* 0.4.4 */
    .domainGetMaxVcpus = qemudDomainGetMaxVcpus, /* 0.4.4 */
    .domainGetSecurityLabel = qemudDomainGetSecurityLabel, /* 0.6.1 */
    .nodeGetSecurityModel = qemudNodeGetSecurityModel, /* 0.6.1 */
    .domainGetXMLDesc = qemuDomainGetXMLDesc, /* 0.2.0 */
    .domainXMLFromNative = qemuDomainXMLFromNative, /* 0.6.4 */
    .domainXMLToNative = qemuDomainXMLToNative, /* 0.6.4 */
    .listDefinedDomains = qemudListDefinedDomains, /* 0.2.0 */
    .numOfDefinedDomains = qemudNumDefinedDomains, /* 0.2.0 */
    .domainCreate = qemuDomainStart, /* 0.2.0 */
    .domainCreateWithFlags = qemuDomainStartWithFlags, /* 0.8.2 */
    .domainDefineXML = qemudDomainDefine, /* 0.2.0 */
    .domainUndefine = qemudDomainUndefine, /* 0.2.0 */
    .domainUndefineFlags = qemuDomainUndefineFlags, /* 0.9.4 */
    .domainAttachDevice = qemuDomainAttachDevice, /* 0.4.1 */
    .domainAttachDeviceFlags = qemuDomainAttachDeviceFlags, /* 0.7.7 */
    .domainDetachDevice = qemuDomainDetachDevice, /* 0.5.0 */
    .domainDetachDeviceFlags = qemuDomainDetachDeviceFlags, /* 0.7.7 */
    .domainUpdateDeviceFlags = qemuDomainUpdateDeviceFlags, /* 0.8.0 */
    .domainGetAutostart = qemudDomainGetAutostart, /* 0.2.1 */
    .domainSetAutostart = qemudDomainSetAutostart, /* 0.2.1 */
    .domainGetSchedulerType = qemuGetSchedulerType, /* 0.7.0 */
    .domainGetSchedulerParameters = qemuGetSchedulerParameters, /* 0.7.0 */
    .domainGetSchedulerParametersFlags = qemuGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = qemuSetSchedulerParameters, /* 0.7.0 */
    .domainSetSchedulerParametersFlags = qemuSetSchedulerParametersFlags, /* 0.9.2 */
    .domainMigratePerform = qemudDomainMigratePerform, /* 0.5.0 */
    .domainBlockStats = qemudDomainBlockStats, /* 0.4.1 */
    .domainInterfaceStats = qemudDomainInterfaceStats, /* 0.4.1 */
    .domainMemoryStats = qemudDomainMemoryStats, /* 0.7.5 */
    .domainBlockPeek = qemudDomainBlockPeek, /* 0.4.4 */
    .domainMemoryPeek = qemudDomainMemoryPeek, /* 0.4.4 */
    .domainGetBlockInfo = qemuDomainGetBlockInfo, /* 0.8.1 */
    .nodeGetCPUStats = nodeGetCPUStats, /* 0.9.3 */
    .nodeGetMemoryStats = nodeGetMemoryStats, /* 0.9.3 */
    .nodeGetCellsFreeMemory = nodeGetCellsFreeMemory, /* 0.4.4 */
    .nodeGetFreeMemory = nodeGetFreeMemory, /* 0.4.4 */
    .domainEventRegister = qemuDomainEventRegister, /* 0.5.0 */
    .domainEventDeregister = qemuDomainEventDeregister, /* 0.5.0 */
    .domainMigratePrepare2 = qemudDomainMigratePrepare2, /* 0.5.0 */
    .domainMigrateFinish2 = qemudDomainMigrateFinish2, /* 0.5.0 */
    .nodeDeviceDettach = qemudNodeDeviceDettach, /* 0.6.1 */
    .nodeDeviceReAttach = qemudNodeDeviceReAttach, /* 0.6.1 */
    .nodeDeviceReset = qemudNodeDeviceReset, /* 0.6.1 */
    .domainMigratePrepareTunnel = qemudDomainMigratePrepareTunnel, /* 0.7.2 */
    .isEncrypted = qemuIsEncrypted, /* 0.7.3 */
    .isSecure = qemuIsSecure, /* 0.7.3 */
    .domainIsActive = qemuDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = qemuDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = qemuDomainIsUpdated, /* 0.8.6 */
    .cpuCompare = qemuCPUCompare, /* 0.7.5 */
    .cpuBaseline = qemuCPUBaseline, /* 0.7.7 */
    .domainGetJobInfo = qemuDomainGetJobInfo, /* 0.7.7 */
    .domainAbortJob = qemuDomainAbortJob, /* 0.7.7 */
    .domainMigrateSetMaxDowntime = qemuDomainMigrateSetMaxDowntime, /* 0.8.0 */
    .domainMigrateSetMaxSpeed = qemuDomainMigrateSetMaxSpeed, /* 0.9.0 */
    .domainEventRegisterAny = qemuDomainEventRegisterAny, /* 0.8.0 */
    .domainEventDeregisterAny = qemuDomainEventDeregisterAny, /* 0.8.0 */
    .domainManagedSave = qemuDomainManagedSave, /* 0.8.0 */
    .domainHasManagedSaveImage = qemuDomainHasManagedSaveImage, /* 0.8.0 */
    .domainManagedSaveRemove = qemuDomainManagedSaveRemove, /* 0.8.0 */
    .domainSnapshotCreateXML = qemuDomainSnapshotCreateXML, /* 0.8.0 */
    .domainSnapshotGetXMLDesc = qemuDomainSnapshotGetXMLDesc, /* 0.8.0 */
    .domainSnapshotNum = qemuDomainSnapshotNum, /* 0.8.0 */
    .domainSnapshotListNames = qemuDomainSnapshotListNames, /* 0.8.0 */
    .domainSnapshotLookupByName = qemuDomainSnapshotLookupByName, /* 0.8.0 */
    .domainHasCurrentSnapshot = qemuDomainHasCurrentSnapshot, /* 0.8.0 */
    .domainSnapshotCurrent = qemuDomainSnapshotCurrent, /* 0.8.0 */
    .domainRevertToSnapshot = qemuDomainRevertToSnapshot, /* 0.8.0 */
    .domainSnapshotDelete = qemuDomainSnapshotDelete, /* 0.8.0 */
    .qemuDomainMonitorCommand = qemuDomainMonitorCommand, /* 0.8.3 */
    .qemuDomainAttach = qemuDomainAttach, /* 0.9.4 */
    .domainOpenConsole = qemuDomainOpenConsole, /* 0.8.6 */
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
};


static virStateDriver qemuStateDriver = {
    .name = "QEMU",
    .initialize = qemudStartup,
    .cleanup = qemudShutdown,
    .reload = qemudReload,
    .active = qemudActive,
};

static void
qemuVMDriverLock(void) {
    qemuDriverLock(qemu_driver);
};


static void
qemuVMDriverUnlock(void) {
    qemuDriverUnlock(qemu_driver);
};


static int
qemuVMFilterRebuild(virConnectPtr conn ATTRIBUTE_UNUSED,
                    virHashIterator iter, void *data)
{
    virHashForEach(qemu_driver->domains.objs, iter, data);

    return 0;
}

static virNWFilterCallbackDriver qemuCallbackDriver = {
    .name = "QEMU",
    .vmFilterRebuild = qemuVMFilterRebuild,
    .vmDriverLock = qemuVMDriverLock,
    .vmDriverUnlock = qemuVMDriverUnlock,
};

int qemuRegister(void) {
    virRegisterDriver(&qemuDriver);
    virRegisterStateDriver(&qemuStateDriver);
    virNWFilterRegisterCallbackDriver(&qemuCallbackDriver);
    return 0;
}
