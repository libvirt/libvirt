/*
 * driver.c: core driver methods for managing qemu guests
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
#include "qemu_process.h"
#include "qemu_migration.h"

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
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

#define timeval_to_ms(tv)       (((tv).tv_sec * 1000ull) + ((tv).tv_usec / 1000))

static void processWatchdogEvent(void *data, void *opaque);

static int qemudShutdown(void);

static int qemudDomainObjStart(virConnectPtr conn,
                               struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               bool start_paused);

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
    VIR_ERROR0(_("Failed to initialize security drivers"));
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
        VIR_INFO("Unable to create cgroup for driver: %s",
                 virStrerror(-rc, buf, sizeof(buf)));
    }

    if (qemudLoadDriverConfig(qemu_driver, driverConf) < 0) {
        goto error;
    }
    VIR_FREE(driverConf);

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

    qemuProcessReconnectAll(conn, qemu_driver);

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

    qemuAutostartDomains(qemu_driver);

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


static int qemuDomainSnapshotSetCurrentActive(virDomainObjPtr vm,
                                              char *snapshotDir);
static int qemuDomainSnapshotSetCurrentInactive(virDomainObjPtr vm,
                                                char *snapshotDir);


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

    virCheckFlags(VIR_DOMAIN_START_PAUSED, NULL);

    qemuDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
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

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup; /* XXXX free the 'vm' we created ? */

    if (qemuProcessStart(conn, driver, vm, NULL,
                         (flags & VIR_DOMAIN_START_PAUSED) != 0,
                         -1, NULL, VIR_VM_OP_CREATE) < 0) {
        qemuAuditDomainStart(vm, "booted", false);
        if (qemuDomainObjEndJob(vm) > 0)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    qemuAuditDomainStart(vm, "booted", true);

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
            if (qemuProcessStopCPUs(driver, vm) < 0) {
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
        if (qemuProcessStartCPUs(driver, vm, dom->conn) < 0) {
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

    qemuProcessStop(driver, vm, 0);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    qemuAuditDomainStop(vm, "destroyed");

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

static int qemudDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                                     unsigned int flags) {
    struct qemud_driver *driver = dom->conn->privateData;
    qemuDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1, r;

    virCheckFlags(VIR_DOMAIN_MEM_LIVE |
                  VIR_DOMAIN_MEM_CONFIG, -1);

    if ((flags & (VIR_DOMAIN_MEM_LIVE | VIR_DOMAIN_MEM_CONFIG)) == 0) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("invalid flag combination: (0x%x)"), flags);
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

    if (newmem > vm->def->mem.max_balloon) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("cannot set memory higher than max memory"));
        goto cleanup;
    }

    if (qemuDomainObjBeginJob(vm) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) && (flags & VIR_DOMAIN_MEM_LIVE)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    if (flags & VIR_DOMAIN_MEM_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot change persistent config of a transient domain"));
            goto endjob;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_MEM_LIVE) {
        priv = vm->privateData;
        qemuDomainObjEnterMonitor(vm);
        r = qemuMonitorSetBalloon(priv->mon, newmem);
        qemuDomainObjExitMonitor(vm);
        qemuAuditMemory(vm, vm->def->mem.cur_balloon, newmem, "update", r == 1);
        if (r < 0)
            goto endjob;

        /* Lack of balloon support is a fatal error */
        if (r == 0) {
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                            "%s", _("cannot set memory of an active domain"));
            goto endjob;
        }
    }

    if (flags& VIR_DOMAIN_MEM_CONFIG) {
        persistentDef->mem.cur_balloon = newmem;
        ret = virDomainSaveConfig(driver->configDir, persistentDef);
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

static int qemudDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    return qemudDomainSetMemoryFlags(dom, newmem, VIR_DOMAIN_MEM_LIVE);
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

/* This internal function expects the driver lock to already be held on
 * entry and the vm must be active.
 */
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

    priv->jobActive = QEMU_JOB_SAVE;

    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    /* Pause */
    if (vm->state == VIR_DOMAIN_RUNNING) {
        header.was_running = 1;
        if (qemuProcessStopCPUs(driver, vm) < 0)
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
                            _("Unable to find cgroup for %s"),
                            vm->def->name);
            goto endjob;
        }
        rc = virCgroupAllowDevicePath(cgroup, path,
                                      VIR_CGROUP_DEVICE_RW);
        qemuAuditCgroupPath(vm, cgroup, "allow", path, "rw", rc);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 _("Unable to allow device %s for %s"),
                                 path, vm->def->name);
            goto endjob;
        }
    }

    if ((!bypassSecurityDriver) &&
        virSecurityManagerSetSavedStateLabel(driver->securityManager,
                                             vm, path) < 0)
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

    rc = qemuMigrationWaitForCompletion(driver, vm);

    if (rc < 0)
        goto endjob;

    if ((!bypassSecurityDriver) &&
        virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                 vm, path) < 0)
        VIR_WARN("failed to restore save state label on %s", path);

    if (cgroup != NULL) {
        rc = virCgroupDenyDevicePath(cgroup, path,
                                     VIR_CGROUP_DEVICE_RWM);
        qemuAuditCgroupPath(vm, cgroup, "deny", path, "rwm", rc);
        if (rc < 0)
            VIR_WARN("Unable to deny device %s for %s %d",
                     path, vm->def->name, rc);
    }

    ret = 0;

    /* Shut it down */
    qemuProcessStop(driver, vm, 0);
    qemuAuditDomainStop(vm, "saved");
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
                rc = qemuProcessStartCPUs(driver, vm, dom->conn);
                if (rc < 0)
                    VIR_WARN0("Unable to resume guest CPUs after save failure");
            }

            if (cgroup != NULL) {
                rc = virCgroupDenyDevicePath(cgroup, path,
                                             VIR_CGROUP_DEVICE_RWM);
                qemuAuditCgroupPath(vm, cgroup, "deny", path, "rwm", rc);
                if (rc < 0)
                    VIR_WARN("Unable to deny device %s for %s: %d",
                             path, vm->def->name, rc);
            }

            if ((!bypassSecurityDriver) &&
                virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                         vm, path) < 0)
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

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
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

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
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

    if (virSecurityManagerSetSavedStateLabel(driver->securityManager,
                                             vm, path) < 0)
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

    ret = qemuMigrationWaitForCompletion(driver, vm);

    if (ret < 0)
        goto cleanup;

    if (virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                 vm, path) < 0)
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
        if (qemuProcessStopCPUs(driver, vm) < 0)
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
        qemuProcessStop(driver, vm, 0);
        qemuAuditDomainStop(vm, "crashed");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    }

    /* Since the monitor is always attached to a pty for libvirt, it
       will support synchronous operations so we always get here after
       the migration is complete.  */
    else if (resume && paused && virDomainObjIsActive(vm)) {
        if (qemuProcessStartCPUs(driver, vm, dom->conn) < 0) {
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
    struct qemuDomainWatchdogEvent *wdEvent = data;
    struct qemud_driver *driver = opaque;

    switch (wdEvent->action) {
    case VIR_DOMAIN_WATCHDOG_ACTION_DUMP:
        {
            char *dumpfile;

            if (virAsprintf(&dumpfile, "%s/%s-%u",
                            driver->autoDumpPath,
                            wdEvent->vm->def->name,
                            (unsigned int)time(NULL)) < 0) {
                virReportOOMError();
                break;
            }

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

            ret = qemuProcessStartCPUs(driver, wdEvent->vm, NULL);

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
    int i, rc = 1;
    int ret = -1;
    int oldvcpus = vm->def->vcpus;
    int vcpus = oldvcpus;

    qemuDomainObjEnterMonitor(vm);

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
    qemuDomainObjExitMonitor(vm);
    vm->def->vcpus = vcpus;
    qemuAuditVcpu(vm, oldvcpus, nvcpus, "update", rc == 1);
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
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto error;

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
                            int *fd,
                            pid_t *read_pid,
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
            intermediatefd = *fd;
            *fd = -1;
            if (virExec(intermediate_argv, NULL, NULL,
                        &intermediate_pid, intermediatefd, fd, NULL, 0) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Failed to start decompression binary %s"),
                                intermediate_argv[0]);
                *fd = intermediatefd;
                goto out;
            }
        }
    }

    /* Set the migration source and start it up. */
    ret = qemuProcessStart(conn, driver, vm, "stdio", true, *fd, path,
                           VIR_VM_OP_RESTORE);

    if (intermediate_pid != -1) {
        if (ret < 0) {
            /* if there was an error setting up qemu, the intermediate process will
             * wait forever to write to stdout, so we must manually kill it.
             */
            VIR_FORCE_CLOSE(intermediatefd);
            VIR_FORCE_CLOSE(*fd);
            kill(intermediate_pid, SIGTERM);
        }

        /* Wait for intermediate process to exit */
        while (waitpid(intermediate_pid, &childstat, 0) == -1 &&
               errno == EINTR) {
            /* empty */
        }
    }
    VIR_FORCE_CLOSE(intermediatefd);

    wait_ret = qemudDomainSaveImageClose(*fd, *read_pid, &status);
    *fd = -1;
    if (*read_pid != -1) {
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
    *read_pid = -1;

    if (ret < 0) {
        qemuAuditDomainStart(vm, "restored", false);
        goto out;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    qemuAuditDomainStart(vm, "restored", true);
    if (event)
        qemuDomainEventQueue(driver, event);


    /* If it was running before, resume it now. */
    if (header->was_running) {
        if (qemuProcessStartCPUs(driver, vm, conn) < 0) {
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
    if (virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                 vm, path) < 0)
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

    ret = qemudDomainSaveImageStartVM(conn, driver, vm, &fd,
                                      &read_pid, &header, path);

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

    ret = qemudDomainSaveImageStartVM(conn, driver, vm, &fd,
                                      &read_pid, &header, path);

cleanup:
    virDomainDefFree(def);
    qemudDomainSaveImageClose(fd, read_pid, NULL);
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
    virDomainChrSourceDef monConfig;
    virBitmapPtr qemuCaps = NULL;
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
        int bootIndex = net->bootIndex;
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

    ret = qemuProcessStart(conn, driver, vm, NULL, start_paused, -1, NULL,
                           VIR_VM_OP_CREATE);
    qemuAuditDomainStart(vm, "booted", ret >= 0);
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

    if (qemuCapsProbeMachineTypes(def->emulator, &machines, &nmachines) < 0)
        return -1;

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
        qemuReportError(VIR_ERR_OPERATION_INVALID,
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
    virBitmapPtr qemuCaps = NULL;
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

    if (qemuCapsExtractVersionInfo(vm->def->emulator, vm->def->os.arch,
                                   NULL,
                                   &qemuCaps) < 0)
        goto endjob;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        if (dev->data.disk->driverName != NULL &&
            !STREQ(dev->data.disk->driverName, "qemu")) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unsupported driver name '%s' for disk '%s'"),
                            dev->data.disk->driverName, dev->data.disk->src);
            goto endjob;
        }

        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
            if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) !=0 ) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Unable to find cgroup for %s"),
                                vm->def->name);
                goto endjob;
            }
            if (qemuSetupDiskCgroup(driver, vm, cgroup, dev->data.disk) < 0)
                goto endjob;
        }

        switch (dev->data.disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            ret = qemuDomainChangeEjectableMedia(driver, vm,
                                                 dev->data.disk,
                                                 qemuCaps,
                                                 false);
            if (ret == 0)
                dev->data.disk = NULL;
            break;

        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                ret = qemuDomainAttachUsbMassstorageDevice(driver, vm,
                                                           dev->data.disk, qemuCaps);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
                ret = qemuDomainAttachPciDiskDevice(driver, vm,
                                                    dev->data.disk, qemuCaps);
                if (ret == 0)
                    dev->data.disk = NULL;
            } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
                ret = qemuDomainAttachSCSIDisk(driver, vm,
                                               dev->data.disk, qemuCaps);
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
            if (qemuTeardownDiskCgroup(driver, vm, cgroup, dev->data.disk) < 0)
                VIR_WARN("Failed to teardown cgroup for disk path %s",
                         NULLSTR(dev->data.disk->src));
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        if (dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            ret = qemuDomainAttachPciControllerDevice(driver, vm,
                                                      dev->data.controller, qemuCaps);
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
                                        dev->data.net, qemuCaps);
        if (ret == 0)
            dev->data.net = NULL;
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemuDomainAttachHostDevice(driver, vm,
                                         dev->data.hostdev, qemuCaps);
        if (ret == 0)
            dev->data.hostdev = NULL;
    } else {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("device type '%s' cannot be attached"),
                        virDomainDeviceTypeToString(dev->type));
        goto endjob;
    }

    /* update domain status forcibly because the domain status may be changed
     * even if we attach the device failed. For example, a new controller may
     * be created.
     */
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        ret = -1;

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);

    qemuCapsFree(qemuCaps);
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
    virBitmapPtr qemuCaps = NULL;
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

    if (qemuCapsExtractVersionInfo(vm->def->emulator, vm->def->os.arch,
                                   NULL,
                                   &qemuCaps) < 0)
        goto endjob;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
            if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) !=0 ) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Unable to find cgroup for %s"),
                                vm->def->name);
                goto endjob;
            }
            if (qemuSetupDiskCgroup(driver, vm, cgroup, dev->data.disk) < 0)
                goto endjob;
        }

        switch (dev->data.disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            ret = qemuDomainChangeEjectableMedia(driver, vm,
                                                 dev->data.disk,
                                                 qemuCaps,
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
            if (qemuTeardownDiskCgroup(driver, vm, cgroup, dev->data.disk) < 0)
                VIR_WARN("Failed to teardown cgroup for disk path %s",
                         NULLSTR(dev->data.disk->src));
        }
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

    if (!ret && virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        ret = -1;

endjob:
    if (qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);

    qemuCapsFree(qemuCaps);
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
    virBitmapPtr qemuCaps = NULL;
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

    if (qemuCapsExtractVersionInfo(vm->def->emulator, vm->def->os.arch,
                                   NULL,
                                   &qemuCaps) < 0)
        goto endjob;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
            ret = qemuDomainDetachPciDiskDevice(driver, vm, dev, qemuCaps);
        }
        else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            ret = qemuDomainDetachDiskDevice(driver, vm, dev, qemuCaps);
        } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
            ret = qemuDomainDetachDiskDevice(driver, vm, dev, qemuCaps);
        }
        else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("This type of disk cannot be hot unplugged"));
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        ret = qemuDomainDetachNetDevice(driver, vm, dev, qemuCaps);
    } else if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        if (dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            ret = qemuDomainDetachPciControllerDevice(driver, vm, dev,
                                                      qemuCaps);
        } else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("disk controller bus '%s' cannot be hotunplugged."),
                            virDomainControllerTypeToString(dev->data.controller->type));
            /* fallthrough */
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        ret = qemuDomainDetachHostDevice(driver, vm, dev, qemuCaps);
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
    qemuCapsFree(qemuCaps);
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
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cgroup CPU controller is not mounted"));
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

static int qemuDomainSetBlkioParameters(virDomainPtr dom,
                                         virBlkioParameterPtr params,
                                         int nparams,
                                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);
    qemuDriverLock(driver);
    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
        qemuReportError(VIR_ERR_NO_SUPPORT, _("blkio cgroup isn't mounted"));
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
        virBlkioParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
            int rc;
            if (param->type != VIR_DOMAIN_BLKIO_PARAM_UINT) {
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

cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}

static int qemuDomainGetBlkioParameters(virDomainPtr dom,
                                         virBlkioParameterPtr params,
                                         int *nparams,
                                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    unsigned int val;
    int ret = -1;
    int rc;

    virCheckFlags(0, -1);
    qemuDriverLock(driver);

    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
        qemuReportError(VIR_ERR_NO_SUPPORT, _("blkio cgroup isn't mounted"));
        goto cleanup;
    }

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

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    for (i = 0; i < *nparams; i++) {
        virBlkioParameterPtr param = &params[i];
        val = 0;
        param->value.ui = 0;
        param->type = VIR_DOMAIN_BLKIO_PARAM_UINT;

        switch(i) {
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
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cgroup memory controller is not mounted"));
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

            rc = virCgroupSetMemSwapHardLimit(group, params[i].value.ul);
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
    unsigned long long val;
    int ret = -1;
    int rc;

    qemuDriverLock(driver);

    if (!qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cgroup memory controller is not mounted"));
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
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cgroup CPU controller is not mounted"));
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
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cgroup CPU controller is not mounted"));
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
{
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


/* Migration support. */

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
    ret = qemuMigrationPrepareTunnel(driver, dconn, st,
                                     dname, dom_xml);
    qemuDriverUnlock(driver);

cleanup:
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

    ret = qemuMigrationPrepareDirect(driver, dconn,
                                     uri_in, uri_out,
                                     dname, dom_xml);

cleanup:
    qemuDriverUnlock(driver);
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
    int ret = -1;

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

    ret = qemuMigrationPerform(driver, dom->conn, vm,
                               uri, flags,
                               dname, resource);

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
    virErrorPtr orig_err;

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

    dom = qemuMigrationFinish(driver, dconn, vm, flags, retcode);

cleanup:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
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

    VIR_DEBUG("Requesting migration speed change to %luMbs", bandwidth);
    priv->jobSignals |= QEMU_JOB_SIGNAL_MIGRATE_SPEED;
    priv->jobSignalsData.migrateBandwidth = bandwidth;
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

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        return -1;

    if (vm->state == VIR_DOMAIN_RUNNING) {
        /* savevm monitor command pauses the domain emitting an event which
         * confuses libvirt since it's not notified when qemu resumes the
         * domain. Thus we stop and start CPUs ourselves.
         */
        if (qemuProcessStopCPUs(driver, vm) < 0)
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
        qemuProcessStartCPUs(driver, vm, conn) < 0 &&
        virGetLastError() == NULL) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("resuming after snapshot failed"));
    }

    if (qemuDomainObjEndJob(vm) == 0)
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

    snap->def->state = vm->state;

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

            rc = qemuProcessStart(snapshot->domain->conn, driver, vm, NULL,
                                  false, -1, NULL, VIR_VM_OP_CREATE);
            qemuAuditDomainStart(vm, "from-snapshot", rc >= 0);
            if (qemuDomainSnapshotSetCurrentInactive(vm, driver->snapshotDir) < 0)
                goto endjob;
            if (rc < 0)
                goto endjob;
        }

        if (snap->def->state == VIR_DOMAIN_PAUSED) {
            /* qemu unconditionally starts the domain running again after
             * loadvm, so let's pause it to keep consistency
             */
            rc = qemuProcessStopCPUs(driver, vm);
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
            qemuProcessStop(driver, vm, 0);
            qemuAuditDomainStop(vm, "from-snapshot");
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

    if (!priv->monitor_warned) {
        VIR_INFO("Qemu monitor command '%s' executed; libvirt results may be unpredictable!",
                 cmd);
        priv->monitor_warned = 1;
    }

    hmp = !!(flags & VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP);

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    ret = qemuMonitorArbitraryCommand(priv->mon, cmd, result, hmp);
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

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("character device %s is not using a PTY"),
                        NULLSTR(devname));
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->source.data.file.path, O_RDWR) < 0)
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
    qemuGetSysinfo, /* getSysinfo */
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
    qemudDomainSetMemoryFlags, /* domainSetMemoryFlags */
    qemuDomainSetMemoryParameters, /* domainSetMemoryParameters */
    qemuDomainGetMemoryParameters, /* domainGetMemoryParameters */
    qemuDomainSetBlkioParameters, /* domainSetBlkioParameters */
    qemuDomainGetBlkioParameters, /* domainGetBlkioParameters */
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
    qemuDomainMigrateSetMaxSpeed, /* domainMigrateSetMaxSpeed */
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
    qemuDomainOpenConsole, /* domainOpenConsole */
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
